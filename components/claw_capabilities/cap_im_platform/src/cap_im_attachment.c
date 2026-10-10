/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_im_attachment.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"

#define CAP_IM_ATTACHMENT_PATH_BUF_SIZE 256
#define CAP_IM_ATTACHMENT_INBOX_BUDGET_BYTES (512 * 1024)
#define CAP_IM_ATTACHMENT_PRUNE_MAX_REMOVALS 64
#define CAP_IM_ATTACHMENT_PRUNE_MAX_SKIPPED 8
/* Free-space floor when the download size is unknown. */
#define CAP_IM_ATTACHMENT_MIN_FREE_BYTES (256 * 1024)
/* Headroom kept free on top of a known download size, for sessions, memory and FAT metadata. */
#define CAP_IM_ATTACHMENT_FREE_RESERVE_BYTES (64 * 1024)
/* 2020-01-01 UTC. Earlier wall-clock time means the clock was never set, so mtimes are not ordered. */
#define CAP_IM_ATTACHMENT_MIN_VALID_EPOCH 1577836800
/* Inbox layout is <root>/<platform>/<chat>/<file>: two directory levels above the files. */
#define CAP_IM_ATTACHMENT_INBOX_DIR_DEPTH 2
#define CAP_IM_ATTACHMENT_STT_BOUNDARY "----cap_im_stt_boundary"
#define CAP_IM_ATTACHMENT_STT_TIMEOUT_MS 60000
#define CAP_IM_ATTACHMENT_STT_CHUNK_BYTES 4096
/* Upload chunks and the JSON response share one buffer; it bounds the accepted response size. */
#define CAP_IM_ATTACHMENT_STT_BUF_BYTES (32 * 1024)

typedef struct {
    FILE *file;
    size_t bytes_written;
    size_t max_bytes;
    bool limit_hit;
    bool write_failed;
} cap_im_attachment_download_t;

static uint64_t cap_im_attachment_fnv1a64(const char *text)
{
    uint64_t hash = 1469598103934665603ULL;

    if (!text) {
        return hash;
    }

    while (*text) {
        hash ^= (unsigned char)(*text++);
        hash *= 1099511628211ULL;
    }

    return hash;
}

static void cap_im_attachment_sanitize_component(const char *src,
                                                 char *dst,
                                                 size_t dst_size)
{
    size_t written = 0;

    if (!dst || dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    if (!src || !src[0]) {
        strlcpy(dst, "unknown", dst_size);
        return;
    }

    while (*src && written + 1 < dst_size) {
        unsigned char ch = (unsigned char) * src++;

        if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.') {
            dst[written++] = (char)ch;
        } else {
            dst[written++] = '_';
        }
    }

    dst[written] = '\0';
    if (written == 0) {
        strlcpy(dst, "unknown", dst_size);
    }
}

static const char *cap_im_attachment_basename(const char *path)
{
    const char *slash = NULL;

    if (!path || !path[0]) {
        return "";
    }
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static const char *cap_im_attachment_find_extension(const char *candidate)
{
    const char *basename = NULL;
    const char *end = NULL;
    const char *dot = NULL;

    if (!candidate || !candidate[0]) {
        return NULL;
    }

    basename = cap_im_attachment_basename(candidate);
    end = basename + strcspn(basename, "?#");
    if (end <= basename) {
        return NULL;
    }

    for (dot = end; dot > basename; dot--) {
        if (dot[-1] == '.') {
            size_t ext_len = (size_t)(end - (dot - 1));

            if (ext_len <= 1 || ext_len > 8) {
                return NULL;
            }
            return dot - 1;
        }
        if (dot[-1] == '/' || dot[-1] == '\\') {
            break;
        }
    }

    return NULL;
}

const char *cap_im_attachment_ext_from_mime(const char *mime)
{
    if (!mime || !mime[0]) {
        return ".bin";
    }
    if (strcmp(mime, "image/jpeg") == 0) {
        return ".jpg";
    }
    if (strcmp(mime, "image/png") == 0) {
        return ".png";
    }
    if (strcmp(mime, "image/gif") == 0) {
        return ".gif";
    }
    if (strcmp(mime, "image/webp") == 0) {
        return ".webp";
    }
    if (strcmp(mime, "audio/mpeg") == 0) {
        return ".mp3";
    }
    if (strcmp(mime, "audio/mp3") == 0) {
        return ".mp3";
    }
    if (strcmp(mime, "audio/wav") == 0 || strcmp(mime, "audio/x-wav") == 0) {
        return ".wav";
    }
    if (strcmp(mime, "audio/ogg") == 0) {
        return ".ogg";
    }
    if (strcmp(mime, "audio/aac") == 0) {
        return ".aac";
    }
    if (strcmp(mime, "audio/amr") == 0) {
        return ".amr";
    }
    if (strcmp(mime, "audio/silk") == 0) {
        return ".silk";
    }
    if (strcmp(mime, "audio/mp4") == 0) {
        return ".m4a";
    }
    if (strcmp(mime, "application/pdf") == 0) {
        return ".pdf";
    }
    if (strcmp(mime, "text/plain") == 0) {
        return ".txt";
    }
    return ".bin";
}

const char *cap_im_attachment_guess_extension(const char *path_or_url,
                                              const char *original_filename,
                                              const char *mime)
{
    const char *candidates[2] = {original_filename, path_or_url};
    size_t i;

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        const char *candidate = candidates[i];
        const char *dot = NULL;

        if (!candidate || !candidate[0]) {
            continue;
        }
        dot = cap_im_attachment_find_extension(candidate);
        if (dot && dot[1]) {
            return dot;
        }
    }

    return cap_im_attachment_ext_from_mime(mime);
}

const char *cap_im_attachment_normalize_url(const char *url,
                                            char *buf,
                                            size_t buf_size)
{
    if (!url || !url[0] || !buf || buf_size == 0) {
        return NULL;
    }

    if (strncmp(url, "//", 2) == 0) {
        snprintf(buf, buf_size, "https:%s", url);
    } else {
        snprintf(buf, buf_size, "%s", url);
    }

    return buf;
}

static esp_err_t cap_im_attachment_ensure_dir(const char *path)
{
    struct stat st = {0};

    if (!path || !path[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? ESP_OK : ESP_FAIL;
    }

    if (mkdir(path, 0755) != 0 && errno != EEXIST) {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static esp_err_t cap_im_attachment_ensure_parent_dirs(const char *path)
{
    char dir[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];
    char *cursor = NULL;
    char *slash = NULL;
    char *create_from = NULL;
    struct stat st = {0};

    if (!path || !path[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(dir, path, sizeof(dir));
    slash = strrchr(dir, '/');
    if (!slash) {
        return ESP_OK;
    }
    *slash = '\0';

    if (dir[0] != '/') {
        return ESP_ERR_INVALID_ARG;
    }

    for (cursor = dir + 1; *cursor; cursor++) {
        if (*cursor != '/') {
            continue;
        }

        *cursor = '\0';
        if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            create_from = cursor + 1;
        }
        *cursor = '/';
    }

    if (!create_from) {
        return ESP_FAIL;
    }

    for (cursor = create_from; *cursor; cursor++) {
        if (*cursor == '/') {
            *cursor = '\0';
            if (cap_im_attachment_ensure_dir(dir) != ESP_OK) {
                return ESP_FAIL;
            }
            *cursor = '/';
        }
    }

    return cap_im_attachment_ensure_dir(dir);
}

esp_err_t cap_im_attachment_build_saved_paths(const char *root_dir,
                                              const char *platform_dir,
                                              const char *chat_id,
                                              const char *message_id,
                                              const char *kind,
                                              const char *extension,
                                              char *saved_dir,
                                              size_t saved_dir_size,
                                              char *saved_name,
                                              size_t saved_name_size,
                                              char *saved_path,
                                              size_t saved_path_size)
{
    char safe_chat[64];
    uint64_t message_hash;
    int written;

    if (!root_dir || !root_dir[0] || !platform_dir || !platform_dir[0] || !chat_id ||
            !message_id || !kind || !extension || !saved_dir || !saved_name || !saved_path) {
        return ESP_ERR_INVALID_ARG;
    }

    cap_im_attachment_sanitize_component(chat_id, safe_chat, sizeof(safe_chat));
    written = snprintf(saved_dir, saved_dir_size, "%s/%s/%s", root_dir, platform_dir, safe_chat);
    if (written < 0 || (size_t)written >= saved_dir_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    message_hash = cap_im_attachment_fnv1a64(message_id);
    written = snprintf(saved_name,
                       saved_name_size,
                       "%s_%08" PRIx32 "_%s%s",
                       platform_dir,
                       (uint32_t)message_hash,
                       kind,
                       extension);
    if (written < 0 || (size_t)written >= saved_name_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    written = snprintf(saved_path, saved_path_size, "%s/%s", saved_dir, saved_name);
    if (written < 0 || (size_t)written >= saved_path_size) {
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

static esp_err_t cap_im_attachment_download_event_handler(esp_http_client_event_t *event)
{
    cap_im_attachment_download_t *dl = (cap_im_attachment_download_t *)event->user_data;

    if (!dl || event->event_id != HTTP_EVENT_ON_DATA || event->data_len <= 0) {
        return ESP_OK;
    }

    if (dl->bytes_written + (size_t)event->data_len > dl->max_bytes) {
        dl->limit_hit = true;
        return ESP_FAIL;
    }

    if (fwrite(event->data, 1, (size_t)event->data_len, dl->file) != (size_t)event->data_len) {
        dl->write_failed = true;
        return ESP_FAIL;
    }

    dl->bytes_written += (size_t)event->data_len;
    return ESP_OK;
}

/* Free bytes on the FAT volume holding path. Returns UINT64_MAX if the query fails, so callers
 * treat an unknown free space as sufficient. */
static uint64_t cap_im_attachment_free_bytes(const char *log_tag, const char *path)
{
    char root[32];
    uint64_t total = 0;
    uint64_t free_bytes = 0;
    const char *slash = (path[0] == '/') ? strchr(path + 1, '/') : NULL;
    snprintf(root, sizeof(root), "%.*s", (int)(slash ? (size_t)(slash - path) : strlen(path)), path);
    esp_err_t err = esp_vfs_fat_info(root, &total, &free_bytes);

    if (err != ESP_OK) {
        ESP_LOGW(log_tag, "attachment free space query failed: root=%s err=%s", root, esp_err_to_name(err));
        return UINT64_MAX;
    }
    return free_bytes;
}

static uint64_t cap_im_attachment_gc(const char *log_tag,
                                     const char *root_dir,
                                     const char *keep_path,
                                     uint64_t need_free_bytes);

static esp_err_t cap_im_attachment_ensure_free_space(const char *log_tag,
                                                     const char *root_dir,
                                                     size_t expected_bytes)
{
    uint64_t min_free = expected_bytes ?
                        (uint64_t)expected_bytes + CAP_IM_ATTACHMENT_FREE_RESERVE_BYTES :
                        CAP_IM_ATTACHMENT_MIN_FREE_BYTES;
    uint64_t free_bytes = cap_im_attachment_free_bytes(log_tag, root_dir);

    if (free_bytes >= min_free) {
        return ESP_OK;
    }
    ESP_LOGW(log_tag, "attachment storage low, running GC: free=%u min=%u expected=%u",
             (unsigned int)free_bytes, (unsigned int)min_free, (unsigned int)expected_bytes);
    free_bytes = cap_im_attachment_gc(log_tag, root_dir, NULL, min_free);
    if (free_bytes < min_free) {
        ESP_LOGW(log_tag, "attachment skipped, storage low after GC: free=%u min=%u",
                 (unsigned int)free_bytes, (unsigned int)min_free);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t cap_im_attachment_download_url_to_file(const char *log_tag,
                                                 const char *root_dir,
                                                 const char *url,
                                                 const char *dest_path,
                                                 size_t max_bytes,
                                                 size_t expected_bytes,
                                                 size_t *out_bytes)
{
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    cap_im_attachment_download_t dl = {0};
    FILE *file = NULL;
    esp_err_t err;
    int status;

    if (!root_dir || !root_dir[0] || !url || !url[0] || !dest_path || !dest_path[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    err = cap_im_attachment_ensure_free_space(log_tag, root_dir, expected_bytes);
    if (err != ESP_OK) {
        return err;
    }

    if (cap_im_attachment_ensure_parent_dirs(dest_path) != ESP_OK) {
        ESP_LOGW(log_tag, "attachment mkdir failed: path=%s errno=%d", dest_path, errno);
        return ESP_FAIL;
    }

    file = fopen(dest_path, "wb");
    if (!file) {
        ESP_LOGW(log_tag, "attachment fopen failed: path=%s errno=%d", dest_path, errno);
        return ESP_FAIL;
    }

    dl.file = file;
    dl.max_bytes = max_bytes ? max_bytes : (2 * 1024 * 1024);

    config.url = url;
    config.event_handler = cap_im_attachment_download_event_handler;
    config.user_data = &dl;
    config.timeout_ms = 30000;
    config.buffer_size = 2048;
    config.buffer_size_tx = 1024;
    config.crt_bundle_attach = esp_crt_bundle_attach;

    client = esp_http_client_init(&config);
    if (!client) {
        fclose(file);
        remove(dest_path);
        return ESP_FAIL;
    }

    err = esp_http_client_perform(client);
    status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (fclose(file) != 0) {
        dl.write_failed = true;
    }

    if (dl.write_failed) {
        ESP_LOGW(log_tag, "attachment write failed, storage full? path=%s bytes=%u",
                 dest_path, (unsigned int)dl.bytes_written);
        remove(dest_path);
        return ESP_ERR_NO_MEM;
    }

    if (err != ESP_OK || status < 200 || status >= 300 || dl.limit_hit || dl.bytes_written == 0) {
        ESP_LOGW(log_tag,
                 "attachment download failed: err=%s http=%d bytes=%u limit_hit=%d url=%s",
                 esp_err_to_name(err),
                 status,
                 (unsigned int)dl.bytes_written,
                 dl.limit_hit ? 1 : 0,
                 url);
        remove(dest_path);
        if (dl.limit_hit) {
            return ESP_ERR_INVALID_SIZE;
        }
        return err != ESP_OK ? err : ESP_FAIL;
    }

    if (out_bytes) {
        *out_bytes = dl.bytes_written;
    }

    return ESP_OK;
}

esp_err_t cap_im_attachment_save_buffer_to_file(const char *log_tag,
                                                const char *dest_path,
                                                const unsigned char *buf,
                                                size_t buf_len)
{
    FILE *file = NULL;

    if (!log_tag || !dest_path || !dest_path[0] || (!buf && buf_len > 0)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (cap_im_attachment_ensure_parent_dirs(dest_path) != ESP_OK) {
        ESP_LOGW(log_tag, "attachment mkdir failed: path=%s errno=%d", dest_path, errno);
        return ESP_FAIL;
    }

    file = fopen(dest_path, "wb");
    if (!file) {
        ESP_LOGW(log_tag, "attachment fopen failed: path=%s errno=%d", dest_path, errno);
        return ESP_FAIL;
    }

    if (buf_len > 0 && fwrite(buf, 1, buf_len, file) != buf_len) {
        fclose(file);
        remove(dest_path);
        ESP_LOGW(log_tag, "attachment fwrite failed: path=%s errno=%d", dest_path, errno);
        return ESP_FAIL;
    }

    fclose(file);
    return ESP_OK;
}

/* Retention order: true when (mtime, path) should be removed before the current oldest candidate.
 * An empty oldest_path means no candidate yet. Ties on mtime fall back to path order. Files written
 * while the clock was unset carry the FAT minimum date and therefore sort as oldest. */
static bool cap_im_attachment_is_older(time_t mtime,
                                       const char *path,
                                       time_t oldest_mtime,
                                       const char *oldest_path)
{
    if (oldest_path[0] == '\0') {
        return true;
    }
    if (mtime != oldest_mtime) {
        return mtime < oldest_mtime;
    }
    return strcmp(path, oldest_path) < 0;
}

typedef struct {
    char path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];        /* scan cursor, extended per directory level */
    char oldest_path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE]; /* empty when no deletable file was found */
    const char *keep_path;
    uint64_t skipped[CAP_IM_ATTACHMENT_PRUNE_MAX_SKIPPED]; /* path hashes whose remove() failed */
    size_t skipped_count;
    uint64_t total_bytes;
    uint64_t oldest_bytes;
    time_t oldest_mtime;
} cap_im_attachment_gc_t;

static bool cap_im_attachment_gc_is_skipped(const cap_im_attachment_gc_t *gc, const char *path)
{
    uint64_t hash = cap_im_attachment_fnv1a64(path);

    for (size_t i = 0; i < gc->skipped_count; i++) {
        if (gc->skipped[i] == hash) {
            return true;
        }
    }
    return false;
}

/* Walks gc->path (length len) down `depth` directory levels, summing every regular file into
 * total_bytes and tracking the oldest file that is neither keep_path nor skipped. */
static void cap_im_attachment_gc_scan(cap_im_attachment_gc_t *gc, size_t len, int depth)
{
    DIR *dir = opendir(gc->path);
    struct dirent *entry = NULL;

    if (!dir) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        struct stat st = {0};
        int written;

        if (entry->d_name[0] == '.') {
            continue;
        }
        written = snprintf(gc->path + len, sizeof(gc->path) - len, "/%s", entry->d_name);
        if (written <= 0 || len + (size_t)written >= sizeof(gc->path) || stat(gc->path, &st) != 0) {
            continue;
        }
        if (depth > 0) {
            if (S_ISDIR(st.st_mode)) {
                cap_im_attachment_gc_scan(gc, len + (size_t)written, depth - 1);
            }
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }
        gc->total_bytes += (uint64_t)st.st_size;
        if ((gc->keep_path && strcmp(gc->path, gc->keep_path) == 0) ||
                cap_im_attachment_gc_is_skipped(gc, gc->path) ||
                !cap_im_attachment_is_older(st.st_mtime, gc->path, gc->oldest_mtime, gc->oldest_path)) {
            continue;
        }
        strlcpy(gc->oldest_path, gc->path, sizeof(gc->oldest_path));
        gc->oldest_mtime = st.st_mtime;
        gc->oldest_bytes = (uint64_t)st.st_size;
    }
    gc->path[len] = '\0';
    closedir(dir);
}

static bool cap_im_attachment_gc_goal_met(uint64_t total_bytes, uint64_t free_bytes, uint64_t need_free_bytes)
{
    return total_bytes <= CAP_IM_ATTACHMENT_INBOX_BUDGET_BYTES && free_bytes >= need_free_bytes;
}

/* Deletes the oldest inbox files across all platforms until the inbox fits the budget and the
 * volume has need_free_bytes free (0: no free-space goal), or nothing deletable is left.
 * keep_path (may be NULL) is never deleted. Returns free bytes after the run (UINT64_MAX if unknown). */
static uint64_t cap_im_attachment_gc(const char *log_tag,
                                     const char *root_dir,
                                     const char *keep_path,
                                     uint64_t need_free_bytes)
{
    cap_im_attachment_gc_t gc = {.keep_path = keep_path};
    uint64_t free_bytes = UINT64_MAX;
    uint64_t freed_bytes = 0;
    int attempts = 0;
    int removed = 0;

    if (strlcpy(gc.path, root_dir, sizeof(gc.path)) >= sizeof(gc.path)) {
        return free_bytes;
    }
    /* Attachments are a cache: freeing storage wins over exact ordering, so prune anyway. */
    if (time(NULL) < CAP_IM_ATTACHMENT_MIN_VALID_EPOCH) {
        ESP_LOGW(log_tag, "attachment GC: system clock not set, deletion order may be inaccurate");
    }

    for (;;) {
        gc.total_bytes = 0;
        gc.oldest_path[0] = '\0';
        cap_im_attachment_gc_scan(&gc, strlen(gc.path), CAP_IM_ATTACHMENT_INBOX_DIR_DEPTH);
        free_bytes = cap_im_attachment_free_bytes(log_tag, root_dir);
        if (cap_im_attachment_gc_goal_met(gc.total_bytes, free_bytes, need_free_bytes) ||
                gc.oldest_path[0] == '\0' || attempts >= CAP_IM_ATTACHMENT_PRUNE_MAX_REMOVALS) {
            break;
        }
        attempts++;
        if (remove(gc.oldest_path) != 0) {
            ESP_LOGW(log_tag, "attachment GC remove failed: path=%s errno=%d", gc.oldest_path, errno);
            if (gc.skipped_count == CAP_IM_ATTACHMENT_PRUNE_MAX_SKIPPED) {
                break;
            }
            gc.skipped[gc.skipped_count++] = cap_im_attachment_fnv1a64(gc.oldest_path);
            continue;
        }
        ESP_LOGI(log_tag, "attachment GC removed %s (%u bytes)", gc.oldest_path, (unsigned int)gc.oldest_bytes);
        removed++;
        freed_bytes += gc.oldest_bytes;
    }

    ESP_LOGI(log_tag, "attachment GC done: removed=%d failed=%d freed=%u total=%u budget=%u free=%u",
             removed, attempts - removed, (unsigned int)freed_bytes, (unsigned int)gc.total_bytes,
             (unsigned int)CAP_IM_ATTACHMENT_INBOX_BUDGET_BYTES, (unsigned int)free_bytes);
    return free_bytes;
}

void cap_im_attachment_prune_inbox(const char *log_tag, const char *root_dir, const char *keep_path)
{
    if (!log_tag || !root_dir || !root_dir[0]) {
        return;
    }
    cap_im_attachment_gc(log_tag, root_dir, keep_path, 0);
}

static esp_err_t cap_im_attachment_http_write_all(esp_http_client_handle_t client,
                                                  const char *data,
                                                  size_t len)
{
    size_t total = 0;

    while (total < len) {
        int written = esp_http_client_write(client, data + total, (int)(len - total));

        if (written <= 0) {
            return ESP_FAIL;
        }
        total += (size_t)written;
    }
    return ESP_OK;
}

/* Streams the multipart body: head (model part + file part header), file in chunks, tail. */
static esp_err_t cap_im_attachment_stt_upload(esp_http_client_handle_t client,
                                              const char *head,
                                              size_t head_len,
                                              const char *tail,
                                              size_t tail_len,
                                              FILE *file,
                                              size_t file_size,
                                              char *chunk)
{
    esp_err_t err;

    err = esp_http_client_open(client, (int)(head_len + file_size + tail_len));
    if (err != ESP_OK) {
        return err;
    }
    err = cap_im_attachment_http_write_all(client, head, head_len);
    while (err == ESP_OK) {
        size_t nread = fread(chunk, 1, CAP_IM_ATTACHMENT_STT_CHUNK_BYTES, file);

        if (nread == 0) {
            err = ferror(file) ? ESP_FAIL : ESP_OK;
            break;
        }
        err = cap_im_attachment_http_write_all(client, chunk, nread);
    }
    if (err == ESP_OK) {
        err = cap_im_attachment_http_write_all(client, tail, tail_len);
    }
    if (err == ESP_OK && esp_http_client_fetch_headers(client) < 0) {
        err = ESP_FAIL;
    }
    return err;
}

esp_err_t cap_im_attachment_transcribe_file(const char *log_tag,
                                            const char *base_url,
                                            const char *api_key,
                                            const char *model,
                                            const char *path,
                                            const char *mime,
                                            char **out_text,
                                            char *err_buf,
                                            size_t err_buf_size)
{
    static const char tail[] = "\r\n--" CAP_IM_ATTACHMENT_STT_BOUNDARY "--\r\n";
    struct stat st = {0};
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    FILE *file = NULL;
    char *buf = NULL;
    char *auth = NULL;
    char url[384];
    char head[512];
    cJSON *root = NULL;
    const char *text = NULL;
    size_t base_len;
    int written;
    int head_len;
    int status = 0;
    int resp_len = 0;
    esp_err_t err;

    if (!log_tag || !base_url || !base_url[0] || !api_key || !api_key[0] || !model || !model[0] ||
            !path || !out_text || !err_buf || err_buf_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_text = NULL;
    err_buf[0] = '\0';

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        snprintf(err_buf, err_buf_size, "Audiodatei nicht lesbar");
        return ESP_ERR_NOT_FOUND;
    }

    base_len = strlen(base_url);
    while (base_len > 0 && base_url[base_len - 1] == '/') {
        base_len--;
    }
    written = snprintf(url, sizeof(url), "%.*s/audio/transcriptions", (int)base_len, base_url);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        snprintf(err_buf, err_buf_size, "stt_base_url zu lang");
        return ESP_ERR_INVALID_SIZE;
    }

    head_len = snprintf(head, sizeof(head),
                        "--" CAP_IM_ATTACHMENT_STT_BOUNDARY "\r\n"
                        "Content-Disposition: form-data; name=\"model\"\r\n\r\n"
                        "%s\r\n"
                        "--" CAP_IM_ATTACHMENT_STT_BOUNDARY "\r\n"
                        "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                        "Content-Type: %s\r\n\r\n",
                        model,
                        cap_im_attachment_basename(path),
                        mime && mime[0] ? mime : "application/octet-stream");
    if (head_len < 0 || (size_t)head_len >= sizeof(head)) {
        snprintf(err_buf, err_buf_size, "Multipart-Header zu lang");
        return ESP_ERR_INVALID_SIZE;
    }

    buf = malloc(CAP_IM_ATTACHMENT_STT_BUF_BYTES);
    if (!buf || asprintf(&auth, "Bearer %s", api_key) < 0) {
        free(buf);
        snprintf(err_buf, err_buf_size, "kein Speicher");
        return ESP_ERR_NO_MEM;
    }

    file = fopen(path, "rb");
    if (!file) {
        free(auth);
        free(buf);
        snprintf(err_buf, err_buf_size, "Audiodatei nicht lesbar");
        return ESP_FAIL;
    }

    config.url = url;
    config.method = HTTP_METHOD_POST;
    config.timeout_ms = CAP_IM_ATTACHMENT_STT_TIMEOUT_MS;
    config.buffer_size = 2048;
    config.buffer_size_tx = 2048;
    config.crt_bundle_attach = esp_crt_bundle_attach;

    client = esp_http_client_init(&config);
    if (!client) {
        fclose(file);
        free(auth);
        free(buf);
        snprintf(err_buf, err_buf_size, "HTTP-Client-Init fehlgeschlagen");
        return ESP_FAIL;
    }
    esp_http_client_set_header(client, "Content-Type",
                               "multipart/form-data; boundary=" CAP_IM_ATTACHMENT_STT_BOUNDARY);
    esp_http_client_set_header(client, "Authorization", auth);

    err = cap_im_attachment_stt_upload(client, head, (size_t)head_len, tail, sizeof(tail) - 1,
                                       file, (size_t)st.st_size, buf);
    if (err == ESP_OK) {
        status = esp_http_client_get_status_code(client);
        resp_len = esp_http_client_read_response(client, buf, CAP_IM_ATTACHMENT_STT_BUF_BYTES - 1);
    }
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    fclose(file);
    free(auth);

    if (err != ESP_OK) {
        ESP_LOGW(log_tag, "STT request failed: url=%s err=%s", url, esp_err_to_name(err));
        snprintf(err_buf, err_buf_size, "Verbindung fehlgeschlagen (%s)", esp_err_to_name(err));
        free(buf);
        return err;
    }
    buf[resp_len > 0 ? resp_len : 0] = '\0';

    root = cJSON_Parse(buf);
    if (status < 200 || status >= 300) {
        cJSON *error_json = cJSON_GetObjectItem(root, "error");
        const char *api_msg = cJSON_GetStringValue(cJSON_GetObjectItem(error_json, "message"));

        ESP_LOGW(log_tag, "STT HTTP %d: %.256s", status, buf);
        snprintf(err_buf, err_buf_size, "HTTP %d%s%s", status, api_msg ? ": " : "", api_msg ? api_msg : "");
        err = ESP_FAIL;
    } else {
        text = cJSON_GetStringValue(cJSON_GetObjectItem(root, "text"));
        if (!text) {
            ESP_LOGW(log_tag, "STT response without text: %.256s", buf);
            snprintf(err_buf, err_buf_size, "ungültige Antwort");
            err = ESP_ERR_INVALID_RESPONSE;
        } else if (!(*out_text = strdup(text))) {
            snprintf(err_buf, err_buf_size, "kein Speicher");
            err = ESP_ERR_NO_MEM;
        }
    }

    cJSON_Delete(root);
    free(buf);
    return err;
}

char *cap_im_attachment_build_payload_json(
    const cap_im_attachment_payload_config_t *config)
{
    cJSON *payload = NULL;
    char *payload_json = NULL;

    if (!config || !config->platform || !config->attachment_kind || !config->saved_path ||
            !config->saved_dir || !config->saved_name) {
        return NULL;
    }

    payload = cJSON_CreateObject();
    if (!payload) {
        return NULL;
    }

    cJSON_AddStringToObject(payload, "platform", config->platform);
    cJSON_AddStringToObject(payload, "attachment_kind", config->attachment_kind);
    cJSON_AddStringToObject(payload, "saved_path", config->saved_path);
    cJSON_AddStringToObject(payload, "saved_dir", config->saved_dir);
    cJSON_AddStringToObject(payload, "saved_name", config->saved_name);
    cJSON_AddStringToObject(payload,
                            "original_filename",
                            config->original_filename ? config->original_filename : "");
    cJSON_AddStringToObject(payload, "mime", config->mime ? config->mime : "");
    cJSON_AddNumberToObject(payload, "size_bytes", (double)config->size_bytes);
    cJSON_AddStringToObject(payload, "caption", config->caption ? config->caption : "");
    cJSON_AddNumberToObject(payload, "saved_at_ms", (double)config->saved_at_ms);
    if (config->source_key && config->source_key[0]) {
        cJSON_AddStringToObject(payload,
                                config->source_key,
                                config->source_value ? config->source_value : "");
    }

    payload_json = cJSON_PrintUnformatted(payload);
    cJSON_Delete(payload);
    return payload_json;
}
