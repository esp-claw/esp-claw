/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Read-only VFS over the image tools/pack_system_fs.py builds and the build embeds in the app
 * (see the layout there). Files are served straight from flash-mapped rodata, so an OTA update
 * replaces them together with the firmware and nothing is copied at boot.
 */
#include "app_romfs.h"

#include "sdkconfig.h"

#if CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_vfs.h"
#include "esp_vfs_ops.h"
#include "freertos/FreeRTOS.h"

#define APP_ROMFS_MAX_FILES 8
#define APP_ROMFS_DIR_FLAG  1u

extern const uint8_t _binary_system_fs_bin_start[];
extern const uint8_t _binary_system_fs_bin_end[];

typedef struct {
    uint32_t path_off;
    uint32_t data_off;
    uint32_t size;
    uint32_t flags;
} app_romfs_entry_t;

typedef struct {
    DIR dir;            /* must be first: the VFS layer fills dd_vfs_idx */
    char path[128];
    uint32_t next;
    struct dirent de;
} app_romfs_dir_t;

static const uint8_t *s_image;
static uint32_t s_count;
static struct {
    int32_t entry;      /* -1 when the slot is free */
    uint32_t pos;
} s_files[APP_ROMFS_MAX_FILES];
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

/* The embedded data has no alignment guarantee, so entries are copied out. */
static app_romfs_entry_t app_romfs_entry(uint32_t i)
{
    app_romfs_entry_t e;

    memcpy(&e, s_image + 8 + i * sizeof(e), sizeof(e));
    return e;
}

static const char *app_romfs_path(const app_romfs_entry_t *e)
{
    return (const char *)s_image + e->path_off;
}

/* "/a/b/" -> "a/b" in `out`. */
static bool app_romfs_normalize(const char *path, char *out, size_t size)
{
    size_t len;

    while (*path == '/') {
        path++;
    }
    len = strlen(path);
    while (len && path[len - 1] == '/') {
        len--;
    }
    if (len >= size) {
        return false;
    }
    memcpy(out, path, len);
    out[len] = '\0';
    return true;
}

/* Entry index of `path`; -2 for the root, -1 when missing. */
static int32_t app_romfs_lookup(const char *path)
{
    char rel[128];

    if (!app_romfs_normalize(path, rel, sizeof(rel))) {
        return -1;
    }
    if (!rel[0]) {
        return -2;
    }
    for (uint32_t i = 0; i < s_count; i++) {
        app_romfs_entry_t e = app_romfs_entry(i);

        if (strcmp(app_romfs_path(&e), rel) == 0) {
            return (int32_t)i;
        }
    }
    return -1;
}

static void app_romfs_fill_stat(int32_t idx, struct stat *st)
{
    app_romfs_entry_t e = idx >= 0 ? app_romfs_entry((uint32_t)idx) : (app_romfs_entry_t) { .flags = APP_ROMFS_DIR_FLAG };

    memset(st, 0, sizeof(*st));
    st->st_mode = (e.flags & APP_ROMFS_DIR_FLAG) ? (S_IFDIR | 0555) : (S_IFREG | 0444);
    st->st_size = (off_t)e.size;
}

static int app_romfs_open(const char *path, int flags, int mode)
{
    int32_t idx = app_romfs_lookup(path);
    int fd = -1;

    (void)mode;
    if ((flags & O_ACCMODE) != O_RDONLY) {
        errno = EROFS;
        return -1;
    }
    if (idx < 0 || (app_romfs_entry((uint32_t)idx).flags & APP_ROMFS_DIR_FLAG)) {
        errno = idx == -1 ? ENOENT : EISDIR;
        return -1;
    }
    portENTER_CRITICAL(&s_lock);
    for (int i = 0; i < APP_ROMFS_MAX_FILES; i++) {
        if (s_files[i].entry < 0) {
            s_files[i].entry = idx;
            s_files[i].pos = 0;
            fd = i;
            break;
        }
    }
    portEXIT_CRITICAL(&s_lock);
    if (fd < 0) {
        errno = ENFILE;
    }
    return fd;
}

static bool app_romfs_fd_ok(int fd)
{
    if (fd < 0 || fd >= APP_ROMFS_MAX_FILES || s_files[fd].entry < 0) {
        errno = EBADF;
        return false;
    }
    return true;
}

static ssize_t app_romfs_read(int fd, void *dst, size_t size)
{
    app_romfs_entry_t e;
    size_t n;

    if (!app_romfs_fd_ok(fd)) {
        return -1;
    }
    e = app_romfs_entry((uint32_t)s_files[fd].entry);
    n = s_files[fd].pos >= e.size ? 0 : e.size - s_files[fd].pos;
    n = n < size ? n : size;
    memcpy(dst, s_image + e.data_off + s_files[fd].pos, n);
    s_files[fd].pos += n;
    return (ssize_t)n;
}

static off_t app_romfs_lseek(int fd, off_t offset, int whence)
{
    off_t base;

    if (!app_romfs_fd_ok(fd)) {
        return -1;
    }
    base = whence == SEEK_SET ? 0 : whence == SEEK_CUR ? (off_t)s_files[fd].pos :
           (off_t)app_romfs_entry((uint32_t)s_files[fd].entry).size;
    if ((whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) || base + offset < 0) {
        errno = EINVAL;
        return -1;
    }
    s_files[fd].pos = (uint32_t)(base + offset);
    return base + offset;
}

static int app_romfs_close(int fd)
{
    if (!app_romfs_fd_ok(fd)) {
        return -1;
    }
    s_files[fd].entry = -1;
    return 0;
}

static int app_romfs_fstat(int fd, struct stat *st)
{
    if (!app_romfs_fd_ok(fd)) {
        return -1;
    }
    app_romfs_fill_stat(s_files[fd].entry, st);
    return 0;
}

static int app_romfs_stat(const char *path, struct stat *st)
{
    int32_t idx = app_romfs_lookup(path);

    if (idx == -1) {
        errno = ENOENT;
        return -1;
    }
    app_romfs_fill_stat(idx, st);
    return 0;
}

static DIR *app_romfs_opendir(const char *path)
{
    int32_t idx = app_romfs_lookup(path);
    app_romfs_dir_t *d;

    if (idx == -1 || (idx >= 0 && !(app_romfs_entry((uint32_t)idx).flags & APP_ROMFS_DIR_FLAG))) {
        errno = idx == -1 ? ENOENT : ENOTDIR;
        return NULL;
    }
    d = calloc(1, sizeof(*d));
    if (!d) {
        errno = ENOMEM;
        return NULL;
    }
    app_romfs_normalize(path, d->path, sizeof(d->path));
    return &d->dir;
}

static struct dirent *app_romfs_readdir(DIR *pdir)
{
    app_romfs_dir_t *d = (app_romfs_dir_t *)pdir;
    size_t len = strlen(d->path);

    while (d->next < s_count) {
        app_romfs_entry_t e = app_romfs_entry(d->next++);
        const char *p = app_romfs_path(&e);
        const char *name = len ? p + len + 1 : p;

        /* Direct children only: "<dir>/<name>" with no further '/'. */
        if ((len && (strncmp(p, d->path, len) != 0 || p[len] != '/')) || strchr(name, '/')) {
            continue;
        }
        d->de.d_ino = d->next;
        d->de.d_type = (e.flags & APP_ROMFS_DIR_FLAG) ? DT_DIR : DT_REG;
        strlcpy(d->de.d_name, name, sizeof(d->de.d_name));
        return &d->de;
    }
    return NULL;
}

static int app_romfs_closedir(DIR *pdir)
{
    free(pdir);
    return 0;
}

static int app_romfs_access(const char *path, int amode)
{
    if (app_romfs_lookup(path) == -1) {
        errno = ENOENT;
        return -1;
    }
    if (amode & W_OK) {
        errno = EROFS;
        return -1;
    }
    return 0;
}

static const esp_vfs_dir_ops_t s_dir_ops = {
    .stat = app_romfs_stat,
    .opendir = app_romfs_opendir,
    .readdir = app_romfs_readdir,
    .closedir = app_romfs_closedir,
    .access = app_romfs_access,
};

static const esp_vfs_fs_ops_t s_ops = {
    .lseek = app_romfs_lseek,
    .read = app_romfs_read,
    .open = app_romfs_open,
    .close = app_romfs_close,
    .fstat = app_romfs_fstat,
    .dir = &s_dir_ops,
};

esp_err_t app_romfs_register(const char *base_path)
{
    const uint8_t *image = _binary_system_fs_bin_start;
    size_t image_len = (size_t)(_binary_system_fs_bin_end - _binary_system_fs_bin_start);
    uint32_t count = 0;

    if (image_len >= 8) {
        memcpy(&count, image + 4, sizeof(count));
    }
    if (image_len < 8 || memcmp(image, "ROFS", 4) != 0 || count > (image_len - 8) / sizeof(app_romfs_entry_t)) {
        return ESP_ERR_INVALID_STATE;
    }
    s_image = image;
    s_count = count;
    for (int i = 0; i < APP_ROMFS_MAX_FILES; i++) {
        s_files[i].entry = -1;
    }
    return esp_vfs_register_fs(base_path, &s_ops, ESP_VFS_FLAG_STATIC | ESP_VFS_FLAG_READONLY_FS, NULL);
}
#endif  /* CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED */
