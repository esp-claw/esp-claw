/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "http_server_priv.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "http_server";

char *http_server_alloc_scratch_buffer(void)
{
    return heap_caps_malloc_prefer(HTTP_SERVER_SCRATCH_SIZE,
                                   2,
                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT,
                                   MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

bool http_server_path_is_safe(const char *path)
{
    return path && path[0] == '/' && strstr(path, "..") == NULL;
}

void http_server_url_decode_inplace(char *value)
{
    if (!value) {
        return;
    }

    char *src = value;
    char *dst = value;
    while (*src) {
        if (src[0] == '%' && src[1] && src[2]) {
            char hi = src[1];
            char lo = src[2];
            uint8_t decoded = 0;

            if (hi >= '0' && hi <= '9') {
                decoded = (uint8_t)(hi - '0') << 4;
            } else if (hi >= 'A' && hi <= 'F') {
                decoded = (uint8_t)(hi - 'A' + 10) << 4;
            } else if (hi >= 'a' && hi <= 'f') {
                decoded = (uint8_t)(hi - 'a' + 10) << 4;
            } else {
                *dst++ = *src++;
                continue;
            }

            if (lo >= '0' && lo <= '9') {
                decoded |= (uint8_t)(lo - '0');
            } else if (lo >= 'A' && lo <= 'F') {
                decoded |= (uint8_t)(lo - 'A' + 10);
            } else if (lo >= 'a' && lo <= 'f') {
                decoded |= (uint8_t)(lo - 'a' + 10);
            } else {
                *dst++ = *src++;
                continue;
            }

            *dst++ = (char)decoded;
            src += 3;
            continue;
        }

        if (*src == '+') {
            *dst++ = ' ';
            src++;
            continue;
        }

        *dst++ = *src++;
    }

    *dst = '\0';
}

esp_err_t http_server_query_get(httpd_req_t *req, const char *key, char *value, size_t value_size)
{
    size_t query_len = httpd_req_get_url_query_len(req);
    if (query_len == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    char *query = calloc(1, query_len + 1);
    if (!query) {
        return ESP_ERR_NO_MEM;
    }

    esp_err_t err = httpd_req_get_url_query_str(req, query, query_len + 1);
    if (err == ESP_OK) {
        err = httpd_query_key_value(query, key, value, value_size);
        if (err == ESP_OK) {
            http_server_url_decode_inplace(value);
        }
    }

    free(query);
    return err;
}

esp_err_t http_server_resolve_storage_path(const char *relative_path, char *full_path, size_t full_path_size)
{
    http_server_ctx_t *ctx = http_server_ctx();

    if (!http_server_path_is_safe(relative_path)) {
        return ESP_ERR_INVALID_ARG;
    }

    int written = snprintf(full_path, full_path_size, "%s%s", ctx->storage_base_path, relative_path);
    return (written <= 0 || (size_t)written >= full_path_size) ? ESP_ERR_INVALID_SIZE : ESP_OK;
}

bool http_server_build_child_relative_path(const char *base_path,
                                           const char *entry_name,
                                           char *out_path,
                                           size_t out_path_size)
{
    if (!base_path || !entry_name || !out_path || out_path_size == 0) {
        return false;
    }

    if (strcmp(base_path, "/") == 0) {
        if (strlcpy(out_path, "/", out_path_size) >= out_path_size) {
            return false;
        }
    } else if (strlcpy(out_path, base_path, out_path_size) >= out_path_size) {
        return false;
    }

    if (strcmp(base_path, "/") != 0 && strlcat(out_path, "/", out_path_size) >= out_path_size) {
        return false;
    }

    return strlcat(out_path, entry_name, out_path_size) < out_path_size;
}

/* Streams the request body into a freshly created file. Returns 0 or an errno
 * value (ENOSPC when the volume is full); the partial file is removed on error. */
int http_server_recv_to_file(httpd_req_t *req, const char *path)
{
    char *scratch = http_server_alloc_scratch_buffer();
    if (!scratch) {
        return ENOMEM;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0664);
    if (fd < 0) {
        free(scratch);
        return errno ? errno : EIO;
    }

    int rc = 0;
    int timeouts = 0;
    size_t remaining = req->content_len;
    while (remaining > 0 && rc == 0) {
        int received = httpd_req_recv(req, scratch, MIN(remaining, HTTP_SERVER_SCRATCH_SIZE));
        if (received == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts <= 3) {
            continue;
        }
        if (received <= 0) {
            rc = EIO;
            break;
        }
        ssize_t written = write(fd, scratch, received);
        if (written != received) {
            /* FAT reports a full volume as a short write or ENOSPC. */
            rc = (written >= 0 || errno == ENOSPC) ? ENOSPC : (errno ? errno : EIO);
            break;
        }
        remaining -= received;
    }

    if (close(fd) != 0 && rc == 0) {
        rc = errno ? errno : EIO;
    }
    free(scratch);
    if (rc != 0) {
        ESP_LOGW(TAG, "Writing %s failed: errno %d", path, rc);
        unlink(path);
    }
    return rc;
}

/* Replaces dst with src. FAT cannot rename over an existing file, so an
 * existing dst is moved aside first and restored if the final rename fails. */
int http_server_replace_file(const char *src, const char *dst)
{
    struct stat st;
    if (stat(dst, &st) != 0) {
        return rename(src, dst);
    }
    if (S_ISDIR(st.st_mode)) {
        return -1;
    }

    char backup[HTTP_SERVER_PATH_MAX];
    if (snprintf(backup, sizeof(backup), "%s.davbak", dst) >= (int)sizeof(backup)) {
        return -1;
    }
    unlink(backup);
    if (rename(dst, backup) != 0) {
        return -1;
    }
    if (rename(src, dst) != 0) {
        rename(backup, dst);
        return -1;
    }
    unlink(backup);
    return 0;
}

int http_server_rmdir_recursive(const char *path)
{
    DIR *dir = opendir(path);
    if (!dir) return -1;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[HTTP_SERVER_PATH_MAX];
        strlcpy(child, path, sizeof(child));
        strlcat(child, "/", sizeof(child));
        strlcat(child, entry->d_name, sizeof(child));

        struct stat st = {0};
        if (stat(child, &st) != 0) { closedir(dir); return -1; }

        int rc = S_ISDIR(st.st_mode) ? http_server_rmdir_recursive(child) : unlink(child);
        if (rc != 0) { closedir(dir); return -1; }
    }
    closedir(dir);
    return rmdir(path);
}
