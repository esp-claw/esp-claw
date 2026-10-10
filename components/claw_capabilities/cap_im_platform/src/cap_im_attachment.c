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
#define CAP_IM_ATTACHMENT_MIN_FREE_BYTES (256 * 1024)
/* 2020-01-01 UTC. Earlier wall-clock time means the clock was never set, so mtimes are not ordered. */
#define CAP_IM_ATTACHMENT_MIN_VALID_EPOCH 1577836800

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

static esp_err_t cap_im_attachment_check_free_space(const char *log_tag, const char *path)
{
    char root[32];
    uint64_t total = 0;
    uint64_t free_bytes = 0;
    const char *slash = (path[0] == '/') ? strchr(path + 1, '/') : NULL;
    snprintf(root, sizeof(root), "%.*s", (int)(slash ? (size_t)(slash - path) : strlen(path)), path);
    esp_err_t err = esp_vfs_fat_info(root, &total, &free_bytes);

    if (err != ESP_OK) {
        ESP_LOGW(log_tag, "attachment free space query failed: root=%s err=%s", root, esp_err_to_name(err));
        return ESP_OK;
    }
    if (free_bytes < CAP_IM_ATTACHMENT_MIN_FREE_BYTES) {
        ESP_LOGW(log_tag, "attachment skipped, storage low: free=%u min=%u root=%s",
                 (unsigned int)free_bytes, (unsigned int)CAP_IM_ATTACHMENT_MIN_FREE_BYTES, root);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t cap_im_attachment_download_url_to_file(const char *log_tag,
                                                 const char *url,
                                                 const char *dest_path,
                                                 size_t max_bytes,
                                                 size_t *out_bytes)
{
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    cap_im_attachment_download_t dl = {0};
    FILE *file = NULL;
    esp_err_t err;
    int status;

    if (!url || !url[0] || !dest_path || !dest_path[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    err = cap_im_attachment_check_free_space(log_tag, dest_path);
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
 * An empty oldest_path means no candidate yet. Ties on mtime fall back to path order. */
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

static bool cap_im_attachment_join_path(char *dst, size_t dst_size, const char *dir, const char *name)
{
    int written = snprintf(dst, dst_size, "%s/%s", dir, name);

    return written > 0 && (size_t)written < dst_size;
}

/* Scans <platform_path>/<chat>/<file>. Sets total_bytes to the sum of all regular files (keep_path
 * included) and oldest_path to the oldest file other than keep_path (empty if there is none).
 * Returns -1 if the platform directory cannot be opened. */
static int cap_im_attachment_find_oldest(const char *platform_path,
                                         const char *keep_path,
                                         char *oldest_path,
                                         size_t oldest_size,
                                         uint64_t *total_bytes)
{
    DIR *platform_dir = NULL;
    struct dirent *chat_entry = NULL;
    time_t oldest_mtime = 0;

    oldest_path[0] = '\0';
    *total_bytes = 0;
    platform_dir = opendir(platform_path);
    if (!platform_dir) {
        return -1;
    }

    while ((chat_entry = readdir(platform_dir)) != NULL) {
        char chat_path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];
        struct dirent *file_entry = NULL;
        struct stat st = {0};
        DIR *chat_dir = NULL;

        if (chat_entry->d_name[0] == '.' ||
                !cap_im_attachment_join_path(chat_path, sizeof(chat_path), platform_path, chat_entry->d_name) ||
                stat(chat_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
            continue;
        }

        chat_dir = opendir(chat_path);
        if (!chat_dir) {
            continue;
        }
        while ((file_entry = readdir(chat_dir)) != NULL) {
            char file_path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];

            if (file_entry->d_name[0] == '.' ||
                    !cap_im_attachment_join_path(file_path, sizeof(file_path), chat_path, file_entry->d_name) ||
                    stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
                continue;
            }

            *total_bytes += (uint64_t)st.st_size;
            if (strcmp(file_path, keep_path) == 0) {
                continue;
            }
            if (cap_im_attachment_is_older(st.st_mtime, file_path, oldest_mtime, oldest_path)) {
                strlcpy(oldest_path, file_path, oldest_size);
                oldest_mtime = st.st_mtime;
            }
        }
        closedir(chat_dir);
    }

    closedir(platform_dir);
    return 0;
}

void cap_im_attachment_prune_inbox(const char *log_tag,
                                   const char *root_dir,
                                   const char *platform_dir,
                                   const char *keep_path)
{
    char platform_path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];
    char oldest_path[CAP_IM_ATTACHMENT_PATH_BUF_SIZE];
    uint64_t total_bytes = 0;

    if (!log_tag || !root_dir || !platform_dir || !keep_path ||
            !cap_im_attachment_join_path(platform_path, sizeof(platform_path), root_dir, platform_dir)) {
        return;
    }

    /* Without a valid clock, mtimes are not ordered and the names carry no time, so the
     * save order is unknown. Skip pruning rather than delete arbitrary attachments. */
    if (time(NULL) < CAP_IM_ATTACHMENT_MIN_VALID_EPOCH) {
        ESP_LOGW(log_tag, "attachment retention skipped: system clock not set, save order unknown");
        return;
    }

    for (int removed = 0; removed < CAP_IM_ATTACHMENT_PRUNE_MAX_REMOVALS; removed++) {
        if (cap_im_attachment_find_oldest(platform_path, keep_path, oldest_path, sizeof(oldest_path),
                                          &total_bytes) != 0) {
            ESP_LOGW(log_tag, "attachment retention scan failed: dir=%s errno=%d", platform_path, errno);
            return;
        }
        if (total_bytes <= CAP_IM_ATTACHMENT_INBOX_BUDGET_BYTES || oldest_path[0] == '\0') {
            return;
        }
        if (remove(oldest_path) != 0) {
            ESP_LOGW(log_tag, "attachment retention remove failed: path=%s errno=%d", oldest_path, errno);
            return;
        }
        ESP_LOGI(log_tag, "attachment retention removed oldest file: %s (inbox %u bytes, budget %u)",
                 oldest_path, (unsigned int)total_bytes, (unsigned int)CAP_IM_ATTACHMENT_INBOX_BUDGET_BYTES);
    }
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
