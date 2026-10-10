/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_ssh_files.h"

#include <string.h>

/* Appends the segments of `path` to `out` ("/seg" each), skipping empty and "." segments. */
static bool cap_ssh_files_append(const char *path, char *out, size_t out_size, size_t *len)
{
    while (*path) {
        size_t seg;

        while (*path == '/') {
            path++;
        }
        seg = strcspn(path, "/");
        if (seg == 2 && path[0] == '.' && path[1] == '.') {
            return false;
        }
        if (seg > 0 && !(seg == 1 && path[0] == '.')) {
            if (*len + 1 + seg >= out_size) {
                return false;
            }
            out[(*len)++] = '/';
            memcpy(out + *len, path, seg);
            *len += seg;
            out[*len] = '\0';
        }
        path += seg;
    }
    return true;
}

bool cap_ssh_files_resolve(const char *workdir, const char *path, char *out, size_t out_size)
{
    char root[CAP_SSH_FILES_PATH_MAX] = "";
    size_t root_len = 0;
    size_t len = 0;

    for (const char *c = path; *c; c++) {
        if ((unsigned char)*c < 0x20 || *c == 0x7f) {
            return false;
        }
    }
    if (workdir[0] != '/' || !cap_ssh_files_append(workdir, root, sizeof(root), &root_len) || root_len == 0 ||
            out_size == 0) {
        return false;
    }
    out[0] = '\0';
    if (path[0] == '/') {
        return cap_ssh_files_append(path, out, out_size, &len) && cap_ssh_files_inside(root, out);
    }
    if (root_len >= out_size) {
        return false;
    }
    memcpy(out, root, root_len + 1);
    len = root_len;
    return cap_ssh_files_append(path, out, out_size, &len);
}

bool cap_ssh_files_inside(const char *root, const char *path)
{
    size_t len = strlen(root);

    return len > 1 && strncmp(path, root, len) == 0 && (path[len] == '\0' || path[len] == '/');
}

int cap_ssh_files_text_len(const char *buf, size_t len)
{
    size_t i = 0;

    while (i < len) {
        unsigned char c = (unsigned char)buf[i];
        size_t n = c < 0x80 ? 1 : c >= 0xc2 && c < 0xe0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : c >= 0xf0 && c < 0xf5 ? 4 : 0;

        if (c == 0 || n == 0) {
            return -1;
        }
        for (size_t k = 1; k < n && i + k < len; k++) {
            if (((unsigned char)buf[i + k] & 0xc0) != 0x80) {
                return -1;
            }
        }
        if (i + n > len) {
            break;
        }
        i += n;
    }
    return (int)i;
}
