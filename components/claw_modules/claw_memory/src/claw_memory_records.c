/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_log.h"

static const char *TAG = "claw_memory_records";

static bool record_json_uint_in_range(const cJSON *item, uint32_t max_value)
{
    double value;

    if (!cJSON_IsNumber(item)) {
        return false;
    }
    value = cJSON_GetNumberValue(item);
    return value >= 0 && value <= max_value && value == (double)(uint32_t)value;
}

static bool record_json_bounded_string(const cJSON *json, const char *key, size_t size)
{
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(json, key));

    return value && strlen(value) < size;
}

esp_err_t claw_memory_record_validate_json(const cJSON *json, char *reason, size_t reason_size)
{
    const cJSON *summary_ids;
    const cJSON *summary_labels;
    const cJSON *importance;
    const cJSON *kind_item;
    const char *kind;
    int i;

    if (!cJSON_IsObject(json) ||
        !record_json_bounded_string(json, "id", sizeof(((claw_memory_item_t *)0)->id)) ||
        !cJSON_GetStringValue(cJSON_GetObjectItem(json, "id"))[0] ||
        !record_json_bounded_string(json, "source", sizeof(((claw_memory_item_t *)0)->source)) ||
        !record_json_bounded_string(json, "content", sizeof(((claw_memory_item_t *)0)->content)) ||
        !record_json_bounded_string(json, "tags", sizeof(((claw_memory_item_t *)0)->tags)) ||
        !record_json_bounded_string(json, "keywords", sizeof(((claw_memory_item_t *)0)->keywords)) ||
        !record_json_uint_in_range(cJSON_GetObjectItem(json, "created_at"), UINT32_MAX) ||
        !record_json_uint_in_range(cJSON_GetObjectItem(json, "updated_at"), UINT32_MAX) ||
        !record_json_uint_in_range(cJSON_GetObjectItem(json, "access_count"), UINT16_MAX) ||
        !cJSON_IsBool(cJSON_GetObjectItem(json, "deleted"))) {
        goto malformed;
    }
    summary_ids = cJSON_GetObjectItem(json, "summary_ids");
    if (!cJSON_IsArray(summary_ids) ||
        cJSON_GetArraySize(summary_ids) > CLAW_MEMORY_MAX_SUMMARIES) {
        goto malformed;
    }
    for (i = 0; i < cJSON_GetArraySize(summary_ids); i++) {
        const cJSON *summary_id = cJSON_GetArrayItem(summary_ids, i);

        if (!record_json_uint_in_range(summary_id, UINT16_MAX) ||
            cJSON_GetNumberValue(summary_id) < 1) {
            goto malformed;
        }
    }
    importance = cJSON_GetObjectItem(json, "importance");
    if (importance && (!record_json_uint_in_range(importance, 5) ||
                       cJSON_GetNumberValue(importance) < 1)) {
        goto malformed;
    }
    kind_item = cJSON_GetObjectItem(json, "kind");
    kind = cJSON_GetStringValue(kind_item);
    if (kind_item && (!kind || strcmp(kind, claw_memory_kind_name(claw_memory_kind_from_name(kind))) != 0)) {
        goto malformed;
    }
    summary_labels = cJSON_GetObjectItem(json, "summary_labels");
    if (summary_labels) {
        if (!cJSON_IsArray(summary_labels) ||
            cJSON_GetArraySize(summary_labels) > CLAW_MEMORY_MAX_SUMMARIES) {
            goto malformed;
        }
        for (i = 0; i < cJSON_GetArraySize(summary_labels); i++) {
            const char *label = cJSON_GetStringValue(cJSON_GetArrayItem(summary_labels, i));

            if (!label || strlen(label) >= CLAW_MEMORY_MAX_LABEL_TEXT) {
                goto malformed;
            }
        }
    }
    return ESP_OK;

malformed:
    if (reason && reason_size > 0) {
        snprintf(reason, reason_size, "records are malformed");
    }
    return ESP_ERR_INVALID_STATE;
}

static esp_err_t records_sidecar_path(char *buf, size_t size, const char *suffix)
{
    int written;

    if (!buf || size == 0 || !suffix) {
        return ESP_ERR_INVALID_ARG;
    }
    written = snprintf(buf, size, "%s%s", s_memory.records_path, suffix);
    return written >= 0 && (size_t)written < size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t records_validate_path(const char *path)
{
    char *raw = NULL;
    char *cursor;
    esp_err_t err;

    err = read_file_dup(path, &raw);
    if (err != ESP_OK) {
        return err;
    }
    if (strlen(raw) != file_size_bytes(path)) {
        free(raw);
        return ESP_ERR_INVALID_STATE;
    }
    cursor = raw;
    while (*cursor) {
        char *newline = strchr(cursor, '\n');
        cJSON *json;

        if (!newline) {
            free(raw);
            return ESP_ERR_INVALID_STATE;
        }
        *newline = '\0';
        if (newline > cursor && newline[-1] == '\r') {
            newline[-1] = '\0';
        }
        if (!cursor[0]) {
            cursor = newline + 1;
            continue;
        }
        json = cJSON_ParseWithOpts(cursor, NULL, true);
        if (claw_memory_record_validate_json(json, NULL, 0) != ESP_OK) {
            cJSON_Delete(json);
            free(raw);
            return ESP_ERR_INVALID_STATE;
        }
        cJSON_Delete(json);
        cursor = newline + 1;
    }
    free(raw);
    return ESP_OK;
}

/* Mirrors what the strict loader accepts: a bounded line holding a valid record. */
static bool records_line_valid(const char *line, size_t raw_len)
{
    cJSON *json;
    bool ok;

    if (raw_len >= CLAW_MEMORY_RECORD_LINE_SIZE - 1) {
        return false;
    }
    json = cJSON_ParseWithOpts(line, NULL, true);
    ok = claw_memory_record_validate_json(json, NULL, 0) == ESP_OK;
    cJSON_Delete(json);
    return ok;
}

/*
 * The primary is append-only, so a torn last line or a damaged middle line must not discard the
 * other records. Returns ESP_ERR_INVALID_STATE only when the file is unusable (NULs followed by
 * data, or only invalid lines). A torn tail (unterminated or zero-filled) is cut off when fix_tail.
 */
static esp_err_t records_scan_primary(bool fix_tail, size_t *out_invalid)
{
    size_t valid = 0;
    size_t invalid = 0;
    char *raw = NULL;
    char *cursor;
    char *newline;
    size_t size;
    size_t text_len;
    size_t i;
    esp_err_t err = read_file_dup(s_memory.records_path, &raw);

    if (err != ESP_OK) {
        return err;
    }
    size = file_size_bytes(s_memory.records_path);
    text_len = strlen(raw);
    /* A zero-filled tail (torn FAT sector) is a torn tail; NULs followed by data are not. */
    for (i = text_len; i < size; i++) {
        if (raw[i]) {
            free(raw);
            return ESP_ERR_INVALID_STATE;
        }
    }
    cursor = raw;
    while ((newline = strchr(cursor, '\n')) != NULL) {
        size_t raw_len = (size_t)(newline - cursor);

        *newline = '\0';
        if (newline > cursor && newline[-1] == '\r') {
            newline[-1] = '\0';
        }
        if (cursor[0]) {
            if (records_line_valid(cursor, raw_len)) {
                valid++;
            } else {
                invalid++;
            }
        }
        cursor = newline + 1;
    }
    if (invalid && !valid) {
        free(raw);
        return ESP_ERR_INVALID_STATE;
    }
    if ((*cursor || text_len < size) && fix_tail) {
        ESP_LOGW(TAG, "Dropping torn last record (%u bytes)", (unsigned)(size - (size_t)(cursor - raw)));
        if (truncate(s_memory.records_path, (off_t)(cursor - raw)) != 0) {
            free(raw);
            return ESP_FAIL;
        }
    }
    free(raw);
    *out_invalid = invalid;
    return ESP_OK;
}

static esp_err_t records_archive_corrupt(char *archive_path,
                                         size_t archive_path_size,
                                         bool *out_archived)
{
    struct stat st = {0};
    unsigned int attempt;

    *out_archived = false;
    if (stat(s_memory.records_path, &st) != 0) {
        return errno == ENOENT ? ESP_OK : ESP_FAIL;
    }
    for (attempt = 0; attempt < 100; attempt++) {
        int written = attempt == 0 ?
            snprintf(archive_path, archive_path_size, "%s.corrupt", s_memory.records_path) :
            snprintf(archive_path, archive_path_size, "%s.corrupt.%u",
                     s_memory.records_path, attempt);

        if (written < 0 || (size_t)written >= archive_path_size) {
            return ESP_ERR_INVALID_SIZE;
        }
        if (stat(archive_path, &st) != 0) {
            if (errno != ENOENT || rename(s_memory.records_path, archive_path) != 0) {
                return ESP_FAIL;
            }
            *out_archived = true;
            return ESP_OK;
        }
    }
    errno = EEXIST;
    return ESP_ERR_INVALID_STATE;
}

static esp_err_t records_promote(const char *source_path)
{
    char archive_path[CLAW_MEMORY_MAX_PATH + 20];
    bool archived = false;
    esp_err_t err = records_archive_corrupt(archive_path, sizeof(archive_path), &archived);

    if (err != ESP_OK) {
        return err;
    }
    if (rename(source_path, s_memory.records_path) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (archived) {
            (void)rename(archive_path, s_memory.records_path);
        }
        errno = saved_errno;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void records_finish_backup_rotation(void)
{
    char old_path[CLAW_MEMORY_MAX_PATH + 8];
    char bak_path[CLAW_MEMORY_MAX_PATH + 8];
    struct stat st = {0};

    if (records_sidecar_path(old_path, sizeof(old_path), ".old") != ESP_OK ||
        records_sidecar_path(bak_path, sizeof(bak_path), ".bak") != ESP_OK ||
        stat(old_path, &st) != 0) {
        return;
    }
    (void)unlink(bak_path);
    (void)rename(old_path, bak_path);
}

/* Looks for a complete replacement copy of a missing primary. .bak is only used when allow_bak. */
static esp_err_t records_find_valid(char *chosen,
                                    size_t chosen_size,
                                    bool *out_any_present,
                                    bool allow_bak)
{
    static const char *const suffixes[] = {".tmp", ".old", ".bak"};
    size_t i;

    chosen[0] = '\0';
    *out_any_present = false;
    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        char path[CLAW_MEMORY_MAX_PATH + 8];
        esp_err_t err;

        if (records_sidecar_path(path, sizeof(path), suffixes[i]) != ESP_OK) {
            return ESP_ERR_INVALID_SIZE;
        }
        if (!allow_bak && i == 2) {
            struct stat st = {0};

            if (stat(path, &st) == 0) {
                *out_any_present = true;
            }
            continue;
        }
        err = records_validate_path(path);
        if (err == ESP_OK) {
            safe_copy(chosen, chosen_size, path);
            return ESP_OK;
        }
        if (err != ESP_ERR_NOT_FOUND) {
            *out_any_present = true;
            if (err != ESP_ERR_INVALID_STATE) {
                return err;
            }
        }
    }
    return ESP_ERR_NOT_FOUND;
}

esp_err_t claw_memory_records_prepare_for_read(void)
{
    char chosen[CLAW_MEMORY_MAX_PATH + 8];
    bool any_present = false;
    size_t invalid = 0;
    esp_err_t err = records_scan_primary(true, &invalid);

    if (err == ESP_OK) {
        if (invalid) {
            ESP_LOGW(TAG, "Skipping %u unreadable record line(s)", (unsigned)invalid);
        }
        records_finish_backup_rotation();
        return ESP_OK;
    }
    /* An existing primary stays authoritative; only /storage repair may replace it. */
    if (err != ESP_ERR_NOT_FOUND) {
        return err;
    }
    err = records_find_valid(chosen, sizeof(chosen), &any_present, false);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        return err;
    }
    if (!chosen[0]) {
        return any_present ? ESP_ERR_INVALID_STATE : ESP_OK;
    }
    err = records_promote(chosen);
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGW(TAG, "Recovered interrupted records replacement from %s", chosen);
    records_finish_backup_rotation();
    return ESP_OK;
}

static esp_err_t records_rewrite_valid(char *archive_path, size_t archive_path_size);

esp_err_t claw_memory_records_check(bool repair,
                                    bool *out_healthy,
                                    char *output,
                                    size_t output_size)
{
    char chosen[CLAW_MEMORY_MAX_PATH + 8];
    bool any_present = false;
    bool primary_damaged;
    size_t invalid = 0;
    esp_err_t err;

    if (!out_healthy || !output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_healthy = false;
    output[0] = '\0';
    err = records_scan_primary(repair, &invalid);
    if (err == ESP_OK) {
        *out_healthy = true;
        if (invalid && repair) {
            char archive_path[CLAW_MEMORY_MAX_PATH + 20];

            err = records_rewrite_valid(archive_path, sizeof(archive_path));
            if (err != ESP_OK) {
                *out_healthy = false;
                snprintf(output, output_size, "Memory records repair failed: %s.",
                         strerror(errno ? errno : EIO));
                return err;
            }
            snprintf(output, output_size,
                     "Memory records: repaired, %u unreadable line(s) archived to %s.",
                     (unsigned)invalid, archive_path);
        } else if (invalid) {
            snprintf(output, output_size, "Memory records: OK (%u unreadable line(s) skipped).",
                     (unsigned)invalid);
        } else {
            snprintf(output, output_size, "Memory records: OK.");
        }
        return ESP_OK;
    }
    if (err != ESP_ERR_NOT_FOUND && err != ESP_ERR_INVALID_STATE) {
        snprintf(output, output_size, "Memory records inspection failed: %s.",
                 strerror(errno ? errno : EIO));
        return err;
    }
    /* Explicit check/repair is the only path that may fall back to .bak. */
    primary_damaged = err == ESP_ERR_INVALID_STATE;
    err = records_find_valid(chosen, sizeof(chosen), &any_present, true);
    any_present = any_present || primary_damaged;
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        snprintf(output, output_size, "Memory records inspection failed: %s.",
                 strerror(errno ? errno : EIO));
        return err;
    }
    if (err == ESP_OK && !repair) {
        snprintf(output, output_size,
                 "Memory records: damaged; recoverable from an interrupted update.");
        return ESP_OK;
    }
    if (err == ESP_OK) {
        err = records_promote(chosen);
        if (err == ESP_OK) {
            *out_healthy = true;
            snprintf(output, output_size,
                     "Memory records recovered; corrupt copy preserved.");
            records_finish_backup_rotation();
            return ESP_OK;
        }
        snprintf(output, output_size, "Memory records recovery copy could not be promoted.");
        return err;
    }
    if (!repair) {
        snprintf(output, output_size, "%s", any_present ?
                 "Memory records: damaged; no complete recovery copy found." :
                 "Memory records: missing.");
        return ESP_OK;
    }
    snprintf(output, output_size,
             "Memory records damaged; no complete recovery copy; restore backup manually.");
    return ESP_ERR_INVALID_STATE;
}

esp_err_t claw_memory_records_prepare_for_default(void)
{
    struct stat st = {0};

    if (stat(s_memory.records_path, &st) == 0) {
        return ESP_OK;
    }
    if (errno != ENOENT) {
        return ESP_FAIL;
    }
    return claw_memory_records_prepare_for_read();
}

static esp_err_t records_buffer_append(char **buf,
                                       size_t *length,
                                       size_t *capacity,
                                       const char *text)
{
    size_t text_len = strlen(text);
    size_t needed;
    char *grown;

    if (text_len > SIZE_MAX - *length - 2) {
        return ESP_ERR_INVALID_SIZE;
    }
    needed = *length + text_len + 2;
    if (needed > *capacity) {
        size_t new_capacity = *capacity ? *capacity : 256;

        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        grown = realloc(*buf, new_capacity);
        if (!grown) {
            return ESP_ERR_NO_MEM;
        }
        *buf = grown;
        *capacity = new_capacity;
    }
    memcpy(*buf + *length, text, text_len);
    *length += text_len;
    (*buf)[(*length)++] = '\n';
    (*buf)[*length] = '\0';
    return ESP_OK;
}

static bool records_json_matches_item(cJSON *json, const claw_memory_item_t *item)
{
    static const char *const string_keys[] = {"id", "source", "content", "tags", "keywords"};
    const char *const string_values[] = {
        item->id, item->source, item->content, item->tags, item->keywords,
    };
    cJSON *summary_ids;
    cJSON *created_at;
    cJSON *updated_at;
    cJSON *access_count;
    cJSON *deleted;
    cJSON *importance;
    const char *kind;
    size_t i;

    if (!cJSON_IsObject(json)) {
        return false;
    }
    for (i = 0; i < sizeof(string_keys) / sizeof(string_keys[0]); i++) {
        const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(json, string_keys[i]));

        if (!value || strcmp(value, string_values[i]) != 0) {
            return false;
        }
    }
    created_at = cJSON_GetObjectItem(json, "created_at");
    updated_at = cJSON_GetObjectItem(json, "updated_at");
    access_count = cJSON_GetObjectItem(json, "access_count");
    deleted = cJSON_GetObjectItem(json, "deleted");
    importance = cJSON_GetObjectItem(json, "importance");
    kind = cJSON_GetStringValue(cJSON_GetObjectItem(json, "kind"));
    if (!cJSON_IsNumber(created_at) || cJSON_GetNumberValue(created_at) != item->created_at ||
        !cJSON_IsNumber(updated_at) || cJSON_GetNumberValue(updated_at) != item->updated_at ||
        !cJSON_IsNumber(access_count) || cJSON_GetNumberValue(access_count) != item->access_count ||
        !cJSON_IsBool(deleted) || cJSON_IsTrue(deleted) != (item->deleted != 0) ||
        !cJSON_IsNumber(importance) || cJSON_GetNumberValue(importance) !=
            (item->importance ? item->importance : 3) ||
        !kind || strcmp(kind, claw_memory_kind_name(item->kind)) != 0) {
        return false;
    }
    summary_ids = cJSON_GetObjectItem(json, "summary_ids");
    if (!cJSON_IsArray(summary_ids) ||
        cJSON_GetArraySize(summary_ids) != item->summary_id_count) {
        return false;
    }
    for (i = 0; i < item->summary_id_count; i++) {
        if (cJSON_GetNumberValue(cJSON_GetArrayItem(summary_ids, (int)i)) != item->summary_ids[i]) {
            return false;
        }
    }
    return cJSON_IsArray(cJSON_GetObjectItem(json, "summary_labels"));
}

/* Replaces the primary with only its valid lines; the old primary is kept as archive_path. */
static esp_err_t records_rewrite_valid(char *archive_path, size_t archive_path_size)
{
    char tmp_path[CLAW_MEMORY_MAX_PATH + 8];
    char *raw = NULL;
    char *out = NULL;
    char *cursor;
    char *newline;
    size_t out_len = 0;
    size_t out_cap = 0;
    bool archived = false;
    bool rolled_back = false;
    esp_err_t err = records_sidecar_path(tmp_path, sizeof(tmp_path), ".tmp");

    if (err == ESP_OK) {
        err = read_file_dup(s_memory.records_path, &raw);
    }
    if (err != ESP_OK) {
        return err;
    }
    cursor = raw;
    while (err == ESP_OK && (newline = strchr(cursor, '\n')) != NULL) {
        size_t raw_len = (size_t)(newline - cursor);

        *newline = '\0';
        if (newline > cursor && newline[-1] == '\r') {
            newline[-1] = '\0';
        }
        if (cursor[0] && records_line_valid(cursor, raw_len)) {
            err = records_buffer_append(&out, &out_len, &out_cap, cursor);
        }
        cursor = newline + 1;
    }
    free(raw);
    if (err == ESP_OK) {
        err = write_file_text(tmp_path, out ? out : "");
    }
    free(out);
    if (err == ESP_OK) {
        err = records_archive_corrupt(archive_path, archive_path_size, &archived);
    }
    if (err == ESP_OK && rename(tmp_path, s_memory.records_path) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (archived) {
            rolled_back = rename(archive_path, s_memory.records_path) == 0;
        }
        errno = saved_errno;
        err = ESP_FAIL;
    }
    if (err != ESP_OK && (!archived || rolled_back)) {
        /* A stale reduced .tmp could be promoted by records_find_valid() later.
         * Keep it when the primary was archived and not restored: then it is
         * the only complete copy of the repaired records (the full original
         * is in the archive). */
        int saved_errno = errno;

        unlink(tmp_path);
        errno = saved_errno;
    } else if (err != ESP_OK) {
        /* Without a primary, the next append would create a fresh one and
         * hide .tmp; block writes until /storage repair promotes it. */
        int saved_errno = errno;

        (void)claw_memory_enter_storage_degraded("records repair left no primary", true);
        errno = saved_errno;
    }
    return err;
}

esp_err_t claw_memory_records_write_snapshot(const claw_memory_item_list_t *items)
{
    char *records_text = NULL;
    size_t length = 0;
    size_t capacity = 0;
    esp_err_t err = ESP_OK;
    size_t i;

    if (!items) {
        return ESP_ERR_INVALID_ARG;
    }
    for (i = 0; i < items->count; i++) {
        cJSON *json = claw_memory_item_to_json(&items->items[i], NULL);
        char *text = json && records_json_matches_item(json, &items->items[i]) ?
            cJSON_PrintUnformatted(json) : NULL;

        cJSON_Delete(json);
        if (!text) {
            err = ESP_ERR_NO_MEM;
            break;
        }
        err = records_buffer_append(&records_text, &length, &capacity, text);
        free(text);
        if (err != ESP_OK) {
            break;
        }
    }
    if (err == ESP_OK) {
        err = write_file_atomic(s_memory.records_path, records_text ? records_text : "");
    }
    if (err != ESP_OK) {
        int saved_errno = errno;

        ESP_LOGE(TAG, "Cannot safely replace memory records: %s",
                 saved_errno == ENOSPC ? "DATA storage is full" :
                 strerror(saved_errno ? saved_errno : EIO));
        errno = saved_errno;
    }
    free(records_text);
    return err;
}
