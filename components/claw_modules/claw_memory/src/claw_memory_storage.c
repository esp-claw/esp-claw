/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_log.h"

static const char *TAG = "claw_memory";

typedef enum {
    CLAW_MEMORY_INDEX_SOURCE_NONE = 0,
    CLAW_MEMORY_INDEX_SOURCE_TARGET,
    CLAW_MEMORY_INDEX_SOURCE_TMP,
    CLAW_MEMORY_INDEX_SOURCE_OLD,
    CLAW_MEMORY_INDEX_SOURCE_BAK,
} claw_memory_index_source_t;

static void claw_memory_item_from_json(cJSON *json, claw_memory_item_t *item);
static esp_err_t claw_memory_archive_corrupt_index(char *archive_path,
                                                   size_t archive_path_size,
                                                   bool *out_archived);

static cJSON *claw_memory_new_index_root(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *summaries = cJSON_CreateArray();
    cJSON *keyword_index = cJSON_CreateObject();

    if (!root || !summaries || !keyword_index) {
        cJSON_Delete(root);
        cJSON_Delete(summaries);
        cJSON_Delete(keyword_index);
        return NULL;
    }
    cJSON_AddNumberToObject(root, "version", 3);
    cJSON_AddNumberToObject(root, "next_summary_id", 1);
    cJSON_AddNumberToObject(root, "last_compact_digest_size", 0);
    cJSON_AddItemToObject(root, "summaries", summaries);
    cJSON_AddItemToObject(root, "keyword_index", keyword_index);
    return root;
}

static esp_err_t claw_memory_index_sidecar_path(char *buf,
                                                size_t size,
                                                const char *suffix)
{
    int written;
    if (!buf || size == 0 || !suffix) {
        return ESP_ERR_INVALID_ARG;
    }
    written = snprintf(buf, size, "%s%s", s_memory.index_path, suffix);
    return written >= 0 && (size_t)written < size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t claw_memory_parse_index_path(const char *path, cJSON **out_root)
{
    char *raw = NULL;
    cJSON *root;
    cJSON *next_summary_id;
    cJSON *last_compact_size;
    esp_err_t err;
    if (!path || !out_root) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_root = NULL;
    err = read_file_dup(path, &raw);
    if (err != ESP_OK) {
        return err;
    }
    if (strlen(raw) != file_size_bytes(path)) {
        free(raw);
        return ESP_ERR_INVALID_STATE;
    }
    root = cJSON_ParseWithOpts(raw, NULL, true);
    free(raw);
    next_summary_id = root ? cJSON_GetObjectItem(root, "next_summary_id") : NULL;
    last_compact_size = root ? cJSON_GetObjectItem(root, "last_compact_digest_size") : NULL;
    if (!root || !cJSON_IsObject(root) ||
        !cJSON_IsNumber(cJSON_GetObjectItem(root, "version")) ||
        cJSON_GetNumberValue(cJSON_GetObjectItem(root, "version")) != 3 ||
        !cJSON_IsNumber(next_summary_id) || next_summary_id->valuedouble < 1 ||
        next_summary_id->valuedouble > UINT16_MAX + 1.0 ||
        next_summary_id->valuedouble != (double)(uint32_t)next_summary_id->valuedouble ||
        !cJSON_IsNumber(last_compact_size) || last_compact_size->valuedouble < 0 ||
        last_compact_size->valuedouble > UINT32_MAX ||
        last_compact_size->valuedouble != (double)(uint32_t)last_compact_size->valuedouble ||
        !cJSON_IsArray(cJSON_GetObjectItem(root, "summaries")) ||
        !cJSON_IsObject(cJSON_GetObjectItem(root, "keyword_index")) ||
        (cJSON_GetObjectItem(root, CLAW_MEMORY_PIPELINE_KEY) &&
         !cJSON_IsObject(cJSON_GetObjectItem(root, CLAW_MEMORY_PIPELINE_KEY)))) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_STATE;
    }
    *out_root = root;
    return ESP_OK;
}

static esp_err_t claw_memory_promote_recovered_index(const char *source_path)
{
    char archive_path[CLAW_MEMORY_MAX_PATH + 20];
    bool archived = false;
    esp_err_t err;

    err = claw_memory_archive_corrupt_index(archive_path, sizeof(archive_path), &archived);
    if (err != ESP_OK) {
        return err;
    }
    if (rename(source_path, s_memory.index_path) != 0) {
        int saved_errno = errno ? errno : EIO;

        if (archived) {
            (void)rename(archive_path, s_memory.index_path);
        }
        errno = saved_errno;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static void claw_memory_finish_index_backup_rotation(void)
{
    char old_path[CLAW_MEMORY_MAX_PATH + 8];
    char bak_path[CLAW_MEMORY_MAX_PATH + 8];
    struct stat st = {0};
    if (claw_memory_index_sidecar_path(old_path, sizeof(old_path), ".old") != ESP_OK ||
        claw_memory_index_sidecar_path(bak_path, sizeof(bak_path), ".bak") != ESP_OK ||
        stat(old_path, &st) != 0) {
        return;
    }
    (void)unlink(bak_path);
    (void)rename(old_path, bak_path);
}

static esp_err_t claw_memory_find_valid_index(cJSON **out_root,
                                              claw_memory_index_source_t *out_source,
                                              char *out_source_path,
                                              size_t source_path_size,
                                              bool *out_any_present)
{
    static const struct {
        claw_memory_index_source_t source;
        const char *suffix;
    } candidates[] = {
        {CLAW_MEMORY_INDEX_SOURCE_TARGET, ""},
        {CLAW_MEMORY_INDEX_SOURCE_TMP, ".tmp"},
        {CLAW_MEMORY_INDEX_SOURCE_OLD, ".old"},
        {CLAW_MEMORY_INDEX_SOURCE_BAK, ".bak"},
    };
    size_t i;
    if (!out_root || !out_source || !out_source_path || source_path_size == 0 ||
        !out_any_present) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_root = NULL;
    *out_source = CLAW_MEMORY_INDEX_SOURCE_NONE;
    *out_any_present = false;
    out_source_path[0] = '\0';
    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        char path[CLAW_MEMORY_MAX_PATH + 8];
        cJSON *root = NULL;
        esp_err_t err;
        if (claw_memory_index_sidecar_path(path, sizeof(path), candidates[i].suffix) != ESP_OK) {
            return ESP_ERR_INVALID_SIZE;
        }
        err = claw_memory_parse_index_path(path, &root);
        if (err == ESP_OK) {
            *out_root = root;
            *out_source = candidates[i].source;
            safe_copy(out_source_path, source_path_size, path);
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

esp_err_t claw_memory_load_index(cJSON **out_root)
{
    cJSON *root = NULL;
    claw_memory_index_source_t source = CLAW_MEMORY_INDEX_SOURCE_NONE;
    char source_path[CLAW_MEMORY_MAX_PATH + 8];
    bool any_present = false;
    esp_err_t err;
    if (!out_root) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_root = NULL;

    err = claw_memory_find_valid_index(&root, &source, source_path,
                                       sizeof(source_path), &any_present);
    if (err == ESP_ERR_NOT_FOUND && !any_present) {
        root = claw_memory_new_index_root();
        if (!root) {
            return ESP_ERR_NO_MEM;
        }
        *out_root = root;
        return ESP_OK;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Memory index is damaged and no valid recovery file exists: %s",
                 s_memory.index_path);
        return err == ESP_ERR_NOT_FOUND ? ESP_ERR_INVALID_STATE : err;
    }
    if (source != CLAW_MEMORY_INDEX_SOURCE_TARGET) {
        err = claw_memory_promote_recovered_index(source_path);
        if (err != ESP_OK) {
            int saved_errno = errno;

            cJSON_Delete(root);
            ESP_LOGE(TAG, "Valid memory index recovery found at %s but promotion failed: %s",
                     source_path, strerror(saved_errno ? saved_errno : EIO));
            errno = saved_errno;
            return err;
        }
        ESP_LOGW(TAG, "Recovered interrupted memory index update from %s", source_path);
    }
    claw_memory_finish_index_backup_rotation();

    /* cJSON_ReplaceItemInObject only takes ownership of the new node when the
     * key already exists; on a malformed/legacy index that is MISSING the key
     * entirely it returns false and leaks the freshly-created node. Delete +
     * add handles both the absent and wrong-type cases without leaking. */
    if (!cJSON_IsArray(cJSON_GetObjectItem(root, "summaries"))) {
        cJSON_DeleteItemFromObject(root, "summaries");
        cJSON_AddItemToObject(root, "summaries", cJSON_CreateArray());
    }
    if (!cJSON_IsNumber(cJSON_GetObjectItem(root, "next_summary_id"))) {
        cJSON_AddNumberToObject(root, "next_summary_id", 1);
    }
    if (!cJSON_IsNumber(cJSON_GetObjectItem(root, "last_compact_digest_size"))) {
        cJSON_AddNumberToObject(root, "last_compact_digest_size", 0);
    }
    if (!cJSON_IsObject(cJSON_GetObjectItem(root, "keyword_index"))) {
        cJSON_DeleteItemFromObject(root, "keyword_index");
        cJSON_AddItemToObject(root, "keyword_index", cJSON_CreateObject());
    }
    {
        cJSON *summaries = cJSON_GetObjectItem(root, "summaries");
        int i;

        for (i = cJSON_GetArraySize(summaries) - 1; i >= 0; i--) {
            cJSON *summary = cJSON_GetArrayItem(summaries, i);
            cJSON *clean = NULL;
            const char *label = cJSON_GetStringValue(cJSON_GetObjectItem(summary, "label"));
            int summary_id = cJSON_GetObjectItem(summary, "summary_id") ?
                cJSON_GetObjectItem(summary, "summary_id")->valueint : 0;
            int ref_count = cJSON_GetObjectItem(summary, "ref_count") ?
                cJSON_GetObjectItem(summary, "ref_count")->valueint : 0;

            if (!label || !label[0]) {
                cJSON_DeleteItemFromArray(summaries, i);
                continue;
            }

            clean = cJSON_CreateObject();
            if (!clean) {
                cJSON_Delete(root);
                return ESP_ERR_NO_MEM;
            }
            cJSON_AddNumberToObject(clean, "summary_id", summary_id > 0 ? summary_id : 0);
            cJSON_AddStringToObject(clean, "label", label);
            cJSON_AddNumberToObject(clean, "ref_count", ref_count > 0 ? ref_count : 0);
            cJSON_ReplaceItemInArray(summaries, i, clean);
        }
    }

    *out_root = root;
    return ESP_OK;
}

esp_err_t claw_memory_index_prepare_for_default(void)
{
    struct stat st = {0};
    cJSON *root = NULL;
    esp_err_t err;

    if (stat(s_memory.index_path, &st) == 0) {
        return ESP_OK;
    }
    if (errno != ENOENT) {
        return ESP_FAIL;
    }
    err = claw_memory_load_index(&root);
    cJSON_Delete(root);
    return err;
}

esp_err_t claw_memory_save_index(cJSON *root)
{
    char *text;
    esp_err_t err;

    if (!root) {
        return ESP_ERR_INVALID_ARG;
    }
    text = cJSON_PrintUnformatted(root);
    if (!text) {
        return ESP_ERR_NO_MEM;
    }
    errno = 0;
    err = write_file_atomic(s_memory.index_path, text);
    if (err != ESP_OK) {
        int saved_errno = errno;

        if (saved_errno == ENOSPC) {
            ESP_LOGE(TAG, "Cannot save memory index: DATA storage is full");
        } else {
            ESP_LOGE(TAG, "Cannot safely replace memory index: %s",
                     strerror(saved_errno ? saved_errno : EIO));
        }
        errno = saved_errno;
    }
    free(text);
    return err;
}

static esp_err_t claw_memory_load_records_strict(claw_memory_item_list_t *out_items,
                                                 char *reason,
                                                 size_t reason_size)
{
    const size_t line_size = CLAW_MEMORY_RECORD_LINE_SIZE;
    claw_memory_item_list_t items = {0};
    claw_memory_item_t *item = NULL;
    char *line = NULL;
    FILE *file = NULL;
    esp_err_t err = ESP_OK;
    if (!out_items || !reason || reason_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out_items, 0, sizeof(*out_items));
    reason[0] = '\0';
    line = calloc(1, line_size);
    item = calloc(1, sizeof(*item));
    if (!line || !item) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }
    errno = 0;
    file = fopen(s_memory.records_path, "rb");
    if (!file) {
        snprintf(reason, reason_size, "records unavailable: %s",
                 strerror(errno ? errno : EIO));
        err = errno == ENOENT ? ESP_ERR_INVALID_STATE : ESP_FAIL;
        goto cleanup;
    }

    while (fgets(line, (int)line_size, file)) {
        size_t len = strlen(line);
        cJSON *json = NULL;
        int idx;

        if (len == 0 || line[len - 1] != '\n') {
            snprintf(reason, reason_size, "records are incomplete or contain an oversized line");
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len == 0) {
            continue;
        }
        json = cJSON_ParseWithOpts(line, NULL, true);
        if (claw_memory_record_validate_json(json, reason, reason_size) != ESP_OK) {
            cJSON_Delete(json);
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        claw_memory_item_from_json(json, item);
        cJSON_Delete(json);
        idx = claw_memory_find_item_index(&items, item->id);
        if (idx >= 0) {
            items.items[idx] = *item;
        } else {
            err = claw_memory_item_list_push(&items, item);
            if (err != ESP_OK) {
                goto cleanup;
            }
        }
    }
    if (ferror(file)) {
        snprintf(reason, reason_size, "records could not be read completely");
        err = ESP_FAIL;
        goto cleanup;
    }

cleanup:
    if (file && fclose(file) != 0 && err == ESP_OK) {
        snprintf(reason, reason_size, "records could not be closed after reading");
        err = ESP_FAIL;
    }
    free(line);
    free(item);
    if (err == ESP_OK) {
        *out_items = items;
    } else {
        claw_memory_item_list_free(&items);
    }
    return err;
}

static esp_err_t claw_memory_rebuild_index_from_records(cJSON **out_root,
                                                        char *reason,
                                                        size_t reason_size)
{
    claw_memory_item_list_t items = {0};
    cJSON *root = NULL;
    esp_err_t err;
    size_t i;
    if (!out_root) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_root = NULL;
    err = claw_memory_load_records_strict(&items, reason, reason_size);
    if (err != ESP_OK) {
        return err;
    }
    root = claw_memory_new_index_root();
    if (!root) {
        claw_memory_item_list_free(&items);
        return ESP_ERR_NO_MEM;
    }

    for (i = 0; i < items.count; i++) {
        claw_memory_item_t *item = &items.items[i];
        char labels[CLAW_MEMORY_MAX_SUMMARIES][CLAW_MEMORY_MAX_LABEL_TEXT];
        size_t label_count = 0;
        size_t j;
        if (item->deleted) {
            continue;
        }
        claw_memory_collect_summary_labels(item, labels, &label_count);
        if (label_count != item->summary_id_count) {
            snprintf(reason, reason_size, "records cannot preserve summary labels and IDs");
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        for (j = 0; j < label_count; j++) {
            int summary_id = 0;
            err = claw_memory_ensure_summary_label(root, labels[j], item->summary_ids[j],
                                                   &summary_id);
            if (err != ESP_OK) {
                goto cleanup;
            }
            if (summary_id != item->summary_ids[j]) {
                snprintf(reason, reason_size, "records contain conflicting summary labels and IDs");
                err = ESP_ERR_INVALID_STATE;
                goto cleanup;
            }
        }
        claw_memory_adjust_summary_stats(root, item, 1);
    }
    claw_memory_rebuild_keyword_index(root, &items);
    *out_root = root;
    root = NULL;
    err = ESP_OK;

cleanup:
    cJSON_Delete(root);
    claw_memory_item_list_free(&items);
    return err;
}

static esp_err_t claw_memory_archive_corrupt_index(char *archive_path,
                                                   size_t archive_path_size,
                                                   bool *out_archived)
{
    struct stat st = {0};
    unsigned int attempt;
    if (!archive_path || archive_path_size == 0 || !out_archived) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_archived = false;
    archive_path[0] = '\0';
    if (stat(s_memory.index_path, &st) != 0) {
        return errno == ENOENT ? ESP_OK : ESP_FAIL;
    }
    for (attempt = 0; attempt < 100; attempt++) {
        int written = attempt == 0 ?
            snprintf(archive_path, archive_path_size, "%s.corrupt", s_memory.index_path) :
            snprintf(archive_path, archive_path_size, "%s.corrupt.%u", s_memory.index_path, attempt);
        if (written < 0 || (size_t)written >= archive_path_size) {
            return ESP_ERR_INVALID_SIZE;
        }
        if (stat(archive_path, &st) != 0) {
            if (errno != ENOENT) {
                return ESP_FAIL;
            }
            if (rename(s_memory.index_path, archive_path) != 0) {
                return ESP_FAIL;
            }
            *out_archived = true;
            return ESP_OK;
        }
    }
    errno = EEXIST;
    return ESP_ERR_INVALID_STATE;
}

static void claw_memory_append_degraded_guidance(char *output,
                                                 size_t output_size,
                                                 bool repaired)
{
    size_t length;

    if (!s_memory.storage_degraded || !output || output_size == 0) {
        return;
    }
    length = strlen(output);
    if (length >= output_size - 1) {
        return;
    }
    snprintf(output + length, output_size - length,
             repaired ? " Restart the device to resume memory." :
             " Memory is disabled; recover or free storage, then restart the device.");
}

static void claw_memory_append_storage_status(char *output,
                                              size_t output_size,
                                              const char *status)
{
    size_t length;

    if (!output || !status || !status[0] || output_size == 0 || strstr(output, status)) {
        return;
    }
    length = strlen(output);
    if (length >= output_size - 1) {
        return;
    }
    snprintf(output + length, output_size - length, "%s%s", length ? "\n" : "", status);
}

esp_err_t claw_memory_storage_check(bool repair, char *output, size_t output_size)
{
    cJSON *root = NULL;
    claw_memory_index_source_t source = CLAW_MEMORY_INDEX_SOURCE_NONE;
    char source_path[CLAW_MEMORY_MAX_PATH + 8];
    char archive_path[CLAW_MEMORY_MAX_PATH + 20];
    char records_status[160];
    char reason[96];
    bool any_present = false;
    bool archived = false;
    bool records_healthy = false;
    esp_err_t err;
    if (!output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    output[0] = '\0';
    if (!s_memory.initialized && !s_memory.storage_degraded) {
        snprintf(output, output_size, "Memory storage is not initialized.");
        return ESP_ERR_INVALID_STATE;
    }

    claw_memory_lock();
    err = claw_memory_records_check(repair, &records_healthy,
                                    records_status, sizeof(records_status));
    if (err != ESP_OK) {
        snprintf(output, output_size, "%s", records_status);
        goto cleanup;
    }
    err = claw_memory_find_valid_index(&root, &source, source_path,
                                       sizeof(source_path), &any_present);
    if (err == ESP_OK && source == CLAW_MEMORY_INDEX_SOURCE_TARGET) {
        snprintf(output, output_size, "Memory index: OK.");
        err = ESP_OK;
        goto cleanup;
    }
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        snprintf(output, output_size, "Memory index inspection failed: %s.",
                 strerror(errno ? errno : EIO));
        goto cleanup;
    }
    if (!repair) {
        if (err == ESP_OK) {
            snprintf(output, output_size,
                     "Memory index: damaged; recoverable from an interrupted update.");
        } else if (!any_present) {
            snprintf(output, output_size, "Memory index: missing.");
        } else {
            snprintf(output, output_size,
                     "Memory index: damaged; no valid recovery copy found.");
        }
        err = ESP_OK;
        goto cleanup;
    }

    cJSON_Delete(root);
    root = NULL;
    err = claw_memory_archive_corrupt_index(archive_path, sizeof(archive_path), &archived);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Memory index repair failed while preserving the corrupt index.");
        goto cleanup;
    }
    if (source != CLAW_MEMORY_INDEX_SOURCE_NONE) {
        err = claw_memory_promote_recovered_index(source_path);
        if (err == ESP_OK) {
            snprintf(output, output_size,
                     "Memory index recovered from an interrupted update; corrupt copy preserved.");
            goto cleanup;
        }
        snprintf(output, output_size, "Memory index recovery copy could not be promoted.");
        goto restore_archive;
    }

    reason[0] = '\0';
    err = claw_memory_rebuild_index_from_records(&root, reason, sizeof(reason));
    if (err != ESP_OK) {
        snprintf(output, output_size, "Memory index repair unsafe: %s.",
                 reason[0] ? reason : "records could not be validated");
        goto restore_archive;
    }
    err = claw_memory_save_index(root);
    if (err == ESP_OK) {
        snprintf(output, output_size,
                 "Memory index repaired from complete records; corrupt copy preserved.");
        goto cleanup;
    }
    snprintf(output, output_size, "Memory index repair failed while writing the replacement.");

restore_archive:
    if (archived && access(s_memory.index_path, F_OK) != 0) {
        (void)rename(archive_path, s_memory.index_path);
    }

cleanup:
    cJSON_Delete(root);
    claw_memory_append_storage_status(output, output_size, records_status);
    if (err == ESP_OK) {
        claw_memory_append_degraded_guidance(output, output_size,
                                             repair && records_healthy &&
                                             s_memory.storage_repair_required);
    }
    claw_memory_unlock();
    return err;
}

cJSON *claw_memory_find_summary_by_label(cJSON *index_root, const char *label)
{
    cJSON *summaries;
    cJSON *item;

    if (!index_root || !label || !label[0]) {
        return NULL;
    }
    summaries = cJSON_GetObjectItem(index_root, "summaries");
    cJSON_ArrayForEach(item, summaries) {
        const char *existing = cJSON_GetStringValue(cJSON_GetObjectItem(item, "label"));
        if (existing && strcmp(existing, label) == 0) {
            return item;
        }
    }
    return NULL;
}

cJSON *claw_memory_find_summary_by_id(cJSON *index_root, int summary_id)
{
    cJSON *summaries;
    cJSON *item;

    if (!index_root || summary_id <= 0) {
        return NULL;
    }
    summaries = cJSON_GetObjectItem(index_root, "summaries");
    cJSON_ArrayForEach(item, summaries) {
        cJSON *id = cJSON_GetObjectItem(item, "summary_id");
        if (cJSON_IsNumber(id) && id->valueint == summary_id) {
            return item;
        }
    }
    return NULL;
}

static int claw_memory_next_summary_id(cJSON *index_root)
{
    cJSON *item = cJSON_GetObjectItem(index_root, "next_summary_id");

    if (!cJSON_IsNumber(item) || item->valueint <= 0) {
        cJSON_DeleteItemFromObject(index_root, "next_summary_id");
        cJSON_AddNumberToObject(index_root, "next_summary_id", 1);
        item = cJSON_GetObjectItem(index_root, "next_summary_id");
    }
    return item->valueint;
}

static void claw_memory_set_next_summary_id(cJSON *index_root, int next_id)
{
    cJSON_DeleteItemFromObject(index_root, "next_summary_id");
    cJSON_AddNumberToObject(index_root, "next_summary_id", next_id);
}

esp_err_t claw_memory_ensure_summary_label(cJSON *index_root,
                                           const char *label,
                                           int preferred_id,
                                           int *out_summary_id)
{
    cJSON *summary;
    cJSON *summaries;
    int next_id;

    if (!index_root || !label || !label[0] || !out_summary_id) {
        return ESP_ERR_INVALID_ARG;
    }

    summary = claw_memory_find_summary_by_label(index_root, label);
    if (summary) {
        *out_summary_id = cJSON_GetObjectItem(summary, "summary_id")->valueint;
        return ESP_OK;
    }

    summaries = cJSON_GetObjectItem(index_root, "summaries");
    if (!cJSON_IsArray(summaries)) {
        return ESP_FAIL;
    }

    next_id = claw_memory_next_summary_id(index_root);
    if (preferred_id > 0 && !claw_memory_find_summary_by_id(index_root, preferred_id)) {
        next_id = preferred_id;
    }

    summary = cJSON_CreateObject();
    if (!summary) {
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddNumberToObject(summary, "summary_id", next_id);
    cJSON_AddStringToObject(summary, "label", label);
    cJSON_AddNumberToObject(summary, "ref_count", 0);
    cJSON_AddItemToArray(summaries, summary);
    if (next_id >= claw_memory_next_summary_id(index_root)) {
        claw_memory_set_next_summary_id(index_root, next_id + 1);
    }
    *out_summary_id = next_id;
    return ESP_OK;
}

void claw_memory_adjust_summary_stats(cJSON *index_root,
                                      const claw_memory_item_t *item,
                                      int ref_delta)
{
    size_t i;

    if (!index_root || !item) {
        return;
    }

    for (i = 0; i < item->summary_id_count && i < CLAW_MEMORY_MAX_SUMMARIES; i++) {
        cJSON *summary = claw_memory_find_summary_by_id(index_root, item->summary_ids[i]);
        cJSON *ref_count;

        if (!summary) {
            continue;
        }
        ref_count = cJSON_GetObjectItem(summary, "ref_count");
        if (!cJSON_IsNumber(ref_count)) {
            cJSON_DeleteItemFromObject(summary, "ref_count");
            cJSON_AddNumberToObject(summary, "ref_count", 0);
            ref_count = cJSON_GetObjectItem(summary, "ref_count");
        }

        ref_count->valueint += ref_delta;
        if (ref_count->valueint < 0) {
            ref_count->valueint = 0;
        }
        ref_count->valuedouble = (double)ref_count->valueint;
    }
}

void claw_memory_remove_unused_summaries(cJSON *index_root)
{
    cJSON *summaries;
    int i;

    if (!index_root) {
        return;
    }

    summaries = cJSON_GetObjectItem(index_root, "summaries");
    if (!cJSON_IsArray(summaries)) {
        return;
    }

    for (i = cJSON_GetArraySize(summaries) - 1; i >= 0; i--) {
        cJSON *item = cJSON_GetArrayItem(summaries, i);
        cJSON *ref_count = cJSON_GetObjectItem(item, "ref_count");
        if (!cJSON_IsNumber(ref_count) || ref_count->valueint <= 0) {
            cJSON_DeleteItemFromArray(summaries, i);
        }
    }
}

void claw_memory_item_list_free(claw_memory_item_list_t *list)
{
    if (!list) {
        return;
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

esp_err_t claw_memory_item_list_push(claw_memory_item_list_t *list,
                                     const claw_memory_item_t *item)
{
    claw_memory_item_t *new_items;
    size_t new_capacity;

    if (!list || !item) {
        return ESP_ERR_INVALID_ARG;
    }
    if (list->count < list->capacity) {
        list->items[list->count++] = *item;
        return ESP_OK;
    }

    new_capacity = list->capacity == 0 ? 8 : list->capacity * 2;
    new_items = realloc(list->items, new_capacity * sizeof(*new_items));
    if (!new_items) {
        return ESP_ERR_NO_MEM;
    }
    list->items = new_items;
    list->capacity = new_capacity;
    list->items[list->count++] = *item;
    return ESP_OK;
}

int claw_memory_find_item_index(const claw_memory_item_list_t *list, const char *memory_id)
{
    size_t i;

    if (!list || !memory_id || !memory_id[0]) {
        return -1;
    }
    for (i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].id, memory_id) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static void claw_memory_read_item_field_string(cJSON *json,
                                               const char *key,
                                               char *dst,
                                               size_t dst_size)
{
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(json, key));

    if (value) {
        safe_copy(dst, dst_size, value);
    }
}

static void claw_memory_item_from_json(cJSON *json, claw_memory_item_t *item)
{
    cJSON *summary_ids;
    size_t i;

    memset(item, 0, sizeof(*item));
    claw_memory_read_item_field_string(json, "id", item->id, sizeof(item->id));
    claw_memory_read_item_field_string(json, "source", item->source, sizeof(item->source));
    claw_memory_read_item_field_string(json, "content", item->content, sizeof(item->content));
    claw_memory_read_item_field_string(json, "tags", item->tags, sizeof(item->tags));
    claw_memory_read_item_field_string(json, "keywords", item->keywords, sizeof(item->keywords));
    item->created_at = (uint32_t)cJSON_GetNumberValue(cJSON_GetObjectItem(json, "created_at"));
    item->updated_at = (uint32_t)cJSON_GetNumberValue(cJSON_GetObjectItem(json, "updated_at"));
    item->access_count = (uint16_t)cJSON_GetNumberValue(cJSON_GetObjectItem(json, "access_count"));
    item->deleted = (uint8_t)cJSON_IsTrue(cJSON_GetObjectItem(json, "deleted"));
    item->importance = (uint8_t)cJSON_GetNumberValue(cJSON_GetObjectItem(json, "importance"));
    item->kind = claw_memory_kind_from_name(cJSON_GetStringValue(cJSON_GetObjectItem(json, "kind")));

    summary_ids = cJSON_GetObjectItem(json, "summary_ids");
    if (cJSON_IsArray(summary_ids)) {
        item->summary_id_count = (uint8_t)cJSON_GetArraySize(summary_ids);
        if (item->summary_id_count > CLAW_MEMORY_MAX_SUMMARIES) {
            item->summary_id_count = CLAW_MEMORY_MAX_SUMMARIES;
        }
        for (i = 0; i < item->summary_id_count; i++) {
            cJSON *entry = cJSON_GetArrayItem(summary_ids, (int)i);
            item->summary_ids[i] = (uint16_t)cJSON_GetNumberValue(entry);
        }
    }
}

cJSON *claw_memory_item_to_json(const claw_memory_item_t *item, cJSON *index_root)
{
    cJSON *json = NULL;
    cJSON *summary_ids = NULL;
    cJSON *summary_labels = NULL;
    size_t i;

    if (!item) {
        return NULL;
    }

    json = cJSON_CreateObject();
    summary_ids = cJSON_CreateArray();
    summary_labels = cJSON_CreateArray();
    if (!json || !summary_ids || !summary_labels) {
        cJSON_Delete(json);
        cJSON_Delete(summary_ids);
        cJSON_Delete(summary_labels);
        return NULL;
    }

    cJSON_AddStringToObject(json, "id", item->id);
    cJSON_AddStringToObject(json, "source", item->source);
    cJSON_AddStringToObject(json, "content", item->content);
    cJSON_AddStringToObject(json, "tags", item->tags);
    cJSON_AddStringToObject(json, "keywords", item->keywords);
    cJSON_AddNumberToObject(json, "created_at", item->created_at);
    cJSON_AddNumberToObject(json, "updated_at", item->updated_at);
    cJSON_AddNumberToObject(json, "access_count", item->access_count);
    cJSON_AddBoolToObject(json, "deleted", item->deleted != 0);
    cJSON_AddNumberToObject(json, "importance", item->importance ? item->importance : 3);
    cJSON_AddStringToObject(json, "kind", claw_memory_kind_name(item->kind));

    for (i = 0; i < item->summary_id_count && i < CLAW_MEMORY_MAX_SUMMARIES; i++) {
        cJSON *summary = index_root ? claw_memory_find_summary_by_id(index_root, item->summary_ids[i]) : NULL;
        const char *label = summary ? cJSON_GetStringValue(cJSON_GetObjectItem(summary, "label")) : NULL;

        cJSON_AddItemToArray(summary_ids, cJSON_CreateNumber(item->summary_ids[i]));
        if (label) {
            cJSON_AddItemToArray(summary_labels, cJSON_CreateString(label));
        }
    }
    cJSON_AddItemToObject(json, "summary_ids", summary_ids);
    cJSON_AddItemToObject(json, "summary_labels", summary_labels);
    return json;
}

esp_err_t claw_memory_append_record(const claw_memory_item_t *item)
{
    cJSON *json = NULL;
    char *text = NULL;
    char *line = NULL;
    esp_err_t err;

    if (!item) {
        return ESP_ERR_INVALID_ARG;
    }

    json = cJSON_CreateObject();
    if (!json) {
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(json, "id", item->id);
    cJSON_AddStringToObject(json, "source", item->source);
    cJSON_AddStringToObject(json, "content", item->content);
    cJSON_AddStringToObject(json, "tags", item->tags);
    cJSON_AddStringToObject(json, "keywords", item->keywords);
    cJSON_AddNumberToObject(json, "created_at", item->created_at);
    cJSON_AddNumberToObject(json, "updated_at", item->updated_at);
    cJSON_AddNumberToObject(json, "access_count", item->access_count);
    cJSON_AddBoolToObject(json, "deleted", item->deleted != 0);
    cJSON_AddNumberToObject(json, "importance", item->importance ? item->importance : 3);
    cJSON_AddStringToObject(json, "kind", claw_memory_kind_name(item->kind));
    {
        cJSON *summary_ids = cJSON_CreateArray();
        size_t i;

        if (!summary_ids) {
            cJSON_Delete(json);
            return ESP_ERR_NO_MEM;
        }
        for (i = 0; i < item->summary_id_count && i < CLAW_MEMORY_MAX_SUMMARIES; i++) {
            cJSON_AddItemToArray(summary_ids, cJSON_CreateNumber(item->summary_ids[i]));
        }
        cJSON_AddItemToObject(json, "summary_ids", summary_ids);
    }

    text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (!text) {
        return ESP_ERR_NO_MEM;
    }

    line = dup_printf("%s\n", text);
    free(text);
    if (!line) {
        return ESP_ERR_NO_MEM;
    }

    err = append_file_text(s_memory.records_path, line);
    free(line);
    return err;
}

esp_err_t claw_memory_load_current_items(claw_memory_item_list_t *out_list)
{
    FILE *file = NULL;
    char *line = NULL;
    claw_memory_item_t *item = NULL;
    claw_memory_item_list_t list = {0};
    const size_t line_size = CLAW_MEMORY_RECORD_LINE_SIZE;

    if (!out_list) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out_list, 0, sizeof(*out_list));

    {
        esp_err_t err = claw_memory_records_prepare_for_read();

        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Memory records are damaged and no valid recovery file exists");
            return err;
        }
    }

    line = calloc(1, line_size);
    item = calloc(1, sizeof(*item));
    if (!line || !item) {
        free(line);
        free(item);
        return ESP_ERR_NO_MEM;
    }

    file = fopen(s_memory.records_path, "r");
    if (!file) {
        free(line);
        free(item);
        if (errno == ENOENT) {
            return ESP_OK;
        }
        ESP_LOGE(TAG, "Failed to open memory records: %s", s_memory.records_path);
        return ESP_FAIL;
    }

    while (fgets(line, (int)line_size, file)) {
        cJSON *json = NULL;
        int idx;

        line[strcspn(line, "\r\n")] = '\0';
        if (!line[0]) {
            continue;
        }

        json = cJSON_Parse(line);
        if (!json) {
            continue;
        }
        claw_memory_item_from_json(json, item);
        cJSON_Delete(json);
        if (!item->id[0]) {
            continue;
        }

        idx = claw_memory_find_item_index(&list, item->id);
        if (idx >= 0) {
            list.items[idx] = *item;
        } else if (claw_memory_item_list_push(&list, item) != ESP_OK) {
            fclose(file);
            free(line);
            free(item);
            claw_memory_item_list_free(&list);
            return ESP_ERR_NO_MEM;
        }
    }
    fclose(file);
    free(line);
    free(item);
    *out_list = list;
    return ESP_OK;
}

int claw_memory_sort_by_priority_desc(const void *a, const void *b)
{
    const claw_memory_item_t *ia = (const claw_memory_item_t *)a;
    const claw_memory_item_t *ib = (const claw_memory_item_t *)b;

    if (ia->access_count != ib->access_count) {
        return (int)ib->access_count - (int)ia->access_count;
    }
    if (ia->updated_at != ib->updated_at) {
        return (ib->updated_at > ia->updated_at) ? 1 : -1;
    }
    return strcmp(ia->id, ib->id);
}

void claw_memory_append_digest_line(const char *action,
                                    const claw_memory_item_t *item,
                                    const char *extra)
{
    char timestamp[16];
    char *line;

    snprintf(timestamp, sizeof(timestamp), "%" PRIu32, claw_memory_now_sec());
    line = dup_printf("%s\t%s\t%s%s%s\n",
                      timestamp,
                      action ? action : "unknown",
                      item && item->id[0] ? item->id : "-",
                      extra ? "\t" : "",
                      extra ? extra : "");
    if (!line) {
        return;
    }
    append_file_text(s_memory.digest_path, line);
    free(line);
}

esp_err_t claw_memory_append_recall_deltas(const char *const *memory_ids,
                                           const uint16_t *counts,
                                           size_t count)
{
    char *text = NULL;
    size_t cap = 0;
    size_t off = 0;
    size_t i;
    uint16_t n;
    esp_err_t err;

    for (i = 0; i < count; i++) {
        cap += (size_t)counts[i] * (strlen(memory_ids[i]) + 40);
    }
    if (cap == 0) {
        return ESP_OK;
    }
    text = calloc(1, cap + 1);
    if (!text) {
        return ESP_ERR_NO_MEM;
    }
    /* Same line format as claw_memory_append_digest_line, replayed by compaction. */
    for (i = 0; i < count; i++) {
        for (n = 0; n < counts[i] && off < cap; n++) {
            int written = snprintf(text + off, cap + 1 - off, "%" PRIu32 "\trecall\t%s\taccess_count+1\n",
                                   claw_memory_now_sec(), memory_ids[i]);

            if (written < 0) {
                break;
            }
            off += (size_t)written;
        }
    }
    err = append_file_text(s_memory.digest_path, text);
    free(text);
    return err;
}

cJSON *claw_memory_pipeline_state(cJSON *index_root)
{
    cJSON *state = cJSON_GetObjectItem(index_root, CLAW_MEMORY_PIPELINE_KEY);

    if (!index_root) {
        return NULL;
    }
    if (!cJSON_IsObject(state)) {
        cJSON_DeleteItemFromObject(index_root, CLAW_MEMORY_PIPELINE_KEY);
        state = cJSON_AddObjectToObject(index_root, CLAW_MEMORY_PIPELINE_KEY);
    }
    return state;
}

static void claw_memory_keyword_index_add_term(cJSON *keyword_index,
                                               const char *memory_id,
                                               const char *term)
{
    cJSON *entry = NULL;
    cJSON *id_item = NULL;
    char normalized[48];
    bool exists = false;

    if (!keyword_index || !memory_id || !memory_id[0] || !term || !term[0]) {
        return;
    }

    safe_copy(normalized, sizeof(normalized), term);
    trim_whitespace(normalized);
    if (!normalized[0]) {
        return;
    }

    entry = cJSON_GetObjectItem(keyword_index, normalized);
    if (!cJSON_IsArray(entry)) {
        entry = cJSON_CreateArray();
        if (!entry) {
            return;
        }
        cJSON_AddItemToObject(keyword_index, normalized, entry);
    }

    cJSON_ArrayForEach(id_item, entry) {
        const char *existing = cJSON_GetStringValue(id_item);
        if (existing && strcmp(existing, memory_id) == 0) {
            exists = true;
            break;
        }
    }
    if (!exists) {
        cJSON_AddItemToArray(entry, cJSON_CreateString(memory_id));
    }
}

static void claw_memory_keyword_index_add_csv(cJSON *keyword_index,
                                              const char *memory_id,
                                              const char *csv_text)
{
    char csv_copy[160];
    char *token = NULL;
    char *saveptr = NULL;

    if (!keyword_index || !memory_id || !memory_id[0] || !csv_text || !csv_text[0]) {
        return;
    }

    safe_copy(csv_copy, sizeof(csv_copy), csv_text);
    token = strtok_r(csv_copy, ",;/|", &saveptr);
    while (token) {
        claw_memory_keyword_index_add_term(keyword_index, memory_id, token);
        token = strtok_r(NULL, ",;/|", &saveptr);
    }
}

void claw_memory_rebuild_keyword_index(cJSON *index_root,
                                       const claw_memory_item_list_t *items)
{
    cJSON *keyword_index = cJSON_CreateObject();
    size_t i;

    if (!index_root || !keyword_index) {
        cJSON_Delete(keyword_index);
        return;
    }

    for (i = 0; items && i < items->count; i++) {
        const claw_memory_item_t *item = &items->items[i];

        if (item->deleted || !item->id[0]) {
            continue;
        }
        claw_memory_keyword_index_add_csv(keyword_index, item->id, item->keywords);
        if (!item->keywords[0]) {
            claw_memory_keyword_index_add_csv(keyword_index, item->id, item->tags);
        }
    }
    /* Replace only takes ownership when the key exists; delete+add handles a
     * root missing keyword_index without leaking the freshly built object
     * (consistent with claw_memory_load_index). */
    cJSON_DeleteItemFromObject(index_root, "keyword_index");
    cJSON_AddItemToObject(index_root, "keyword_index", keyword_index);
}

static int claw_memory_capacity_score(const claw_memory_item_t *item)
{
    int score = 0;

    if (!item) {
        return -1000000;
    }
    score += (int)item->access_count * 3;
    score += (int)(item->updated_at / 3600U);
    return score;
}

static void claw_memory_trim_to_capacity(claw_memory_item_list_t *items)
{
    while (items && items->count > CLAW_MEMORY_MAX_ACTIVE_ITEMS) {
        size_t i;
        size_t remove_idx = 0;
        int lowest_score = claw_memory_capacity_score(&items->items[0]);

        for (i = 1; i < items->count; i++) {
            int score = claw_memory_capacity_score(&items->items[i]);
            if (score < lowest_score) {
                lowest_score = score;
                remove_idx = i;
            }
        }
        if (remove_idx + 1 < items->count) {
            memmove(&items->items[remove_idx],
                    &items->items[remove_idx + 1],
                    (items->count - remove_idx - 1) * sizeof(*items->items));
        }
        items->count--;
    }
}

static size_t claw_memory_index_last_compact_digest_size(cJSON *index_root)
{
    cJSON *item;

    if (!index_root) {
        return 0;
    }
    item = cJSON_GetObjectItem(index_root, "last_compact_digest_size");
    if (!cJSON_IsNumber(item) || item->valuedouble < 0) {
        return 0;
    }
    return (size_t)item->valuedouble;
}

static void claw_memory_set_index_last_compact_digest_size(cJSON *index_root, size_t size)
{
    if (!index_root) {
        return;
    }
    cJSON_DeleteItemFromObject(index_root, "last_compact_digest_size");
    cJSON_AddNumberToObject(index_root, "last_compact_digest_size", (double)size);
}

static void claw_memory_apply_digest_recall_deltas(claw_memory_item_list_t *items,
                                                   cJSON *index_root,
                                                   size_t digest_size)
{
    FILE *file = NULL;
    char line[256];
    size_t start_offset;
    size_t i;

    if (!items || !index_root) {
        return;
    }

    start_offset = claw_memory_index_last_compact_digest_size(index_root);
    if (start_offset >= digest_size) {
        claw_memory_set_index_last_compact_digest_size(index_root, digest_size);
        return;
    }

    file = fopen(s_memory.digest_path, "r");
    if (!file) {
        claw_memory_set_index_last_compact_digest_size(index_root, digest_size);
        return;
    }
    if (fseek(file, (long)start_offset, SEEK_SET) != 0) {
        fclose(file);
        claw_memory_set_index_last_compact_digest_size(index_root, digest_size);
        return;
    }

    while (fgets(line, sizeof(line), file)) {
        char *fields[5] = {0};
        char *saveptr = NULL;
        char *token = strtok_r(line, "\t\r\n", &saveptr);
        int field_count = 0;

        while (token && field_count < 5) {
            fields[field_count++] = token;
            token = strtok_r(NULL, "\t\r\n", &saveptr);
        }
        if (field_count < 4) {
            continue;
        }
        if (strcmp(fields[1], "recall") != 0 || strcmp(fields[3], "access_count+1") != 0) {
            continue;
        }

        for (i = 0; i < items->count; i++) {
            claw_memory_item_t *item = &items->items[i];

            if (strcmp(item->id, fields[2]) != 0) {
                continue;
            }
            if (item->access_count < UINT16_MAX) {
                item->access_count++;
            }
            if (fields[0] && fields[0][0]) {
                unsigned long ts = strtoul(fields[0], NULL, 10);

                if (ts > item->updated_at) {
                    item->updated_at = (uint32_t)ts;
                }
            }
            break;
        }
    }

    fclose(file);
    claw_memory_set_index_last_compact_digest_size(index_root, digest_size);
}

esp_err_t claw_memory_compact_internal(bool append_digest)
{
    claw_memory_item_list_t items = {0};
    claw_memory_item_list_t compacted = {0};
    cJSON *old_index = NULL;
    cJSON *new_index = NULL;
    claw_memory_item_t *scratch_item = NULL;
    size_t digest_size = 0;
    size_t i;
    esp_err_t err;

    scratch_item = calloc(1, sizeof(*scratch_item));
    if (!scratch_item) {
        return ESP_ERR_NO_MEM;
    }

    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        free(scratch_item);
        return err;
    }
    err = claw_memory_load_index(&old_index);
    if (err != ESP_OK) {
        free(scratch_item);
        claw_memory_item_list_free(&items);
        return err;
    }
    digest_size = file_size_bytes(s_memory.digest_path);
    claw_memory_apply_digest_recall_deltas(&items, old_index, digest_size);

    for (i = 0; i < items.count; i++) {
        const claw_memory_item_t *src_item = &items.items[i];
        char dedup_key[80];
        int existing;

        if (src_item->deleted) {
            continue;
        }

        *scratch_item = *src_item;
        claw_memory_build_item_key(scratch_item, dedup_key, sizeof(dedup_key));
        if (!dedup_key[0]) {
            normalize_text_for_key(scratch_item->content, dedup_key, sizeof(dedup_key));
        }
        existing = -1;
        if (dedup_key[0]) {
            size_t j;
            for (j = 0; j < compacted.count; j++) {
                char other_key[80];

                claw_memory_build_item_key(&compacted.items[j], other_key, sizeof(other_key));
                if (!other_key[0]) {
                    normalize_text_for_key(compacted.items[j].content, other_key, sizeof(other_key));
                }
                if (strcmp(other_key, dedup_key) == 0) {
                    existing = (int)j;
                    break;
                }
            }
        }

        if (existing >= 0) {
            claw_memory_item_t *dst = &compacted.items[existing];

            if (scratch_item->access_count > dst->access_count) {
                dst->access_count = scratch_item->access_count;
            }
            if (scratch_item->importance > dst->importance) {
                dst->importance = scratch_item->importance;
            }
            if (scratch_item->updated_at > dst->updated_at) {
                dst->updated_at = scratch_item->updated_at;
                safe_copy(dst->content, sizeof(dst->content), scratch_item->content);
                safe_copy(dst->tags, sizeof(dst->tags), scratch_item->tags);
                safe_copy(dst->source, sizeof(dst->source), scratch_item->source);
            }
            if (scratch_item->created_at &&
                (!dst->created_at || scratch_item->created_at < dst->created_at)) {
                dst->created_at = scratch_item->created_at;
            }
        } else if ((err = claw_memory_item_list_push(&compacted, scratch_item)) != ESP_OK) {
            free(scratch_item);
            cJSON_Delete(old_index);
            claw_memory_item_list_free(&items);
            claw_memory_item_list_free(&compacted);
            return err;
        }
    }

    claw_memory_trim_to_capacity(&compacted);
    new_index = claw_memory_new_index_root();
    if (!new_index) {
        free(scratch_item);
        cJSON_Delete(old_index);
        claw_memory_item_list_free(&items);
        claw_memory_item_list_free(&compacted);
        return ESP_ERR_NO_MEM;
    }

    for (i = 0; i < compacted.count; i++) {
        claw_memory_item_t *item = &compacted.items[i];
        char labels[CLAW_MEMORY_MAX_SUMMARIES][CLAW_MEMORY_MAX_LABEL_TEXT];
        size_t label_count = 0;
        size_t j;

        item->summary_id_count = 0;
        claw_memory_collect_summary_labels(item, labels, &label_count);
        for (j = 0; j < label_count && j < CLAW_MEMORY_MAX_SUMMARIES; j++) {
            int old_id = 0;
            int new_id = 0;

            if (old_index) {
                cJSON *old_summary = claw_memory_find_summary_by_label(old_index, labels[j]);
                if (old_summary) {
                    old_id = cJSON_GetObjectItem(old_summary, "summary_id")->valueint;
                }
            }
            if (claw_memory_ensure_summary_label(new_index, labels[j], old_id, &new_id) != ESP_OK) {
                continue;
            }
            item->summary_ids[item->summary_id_count++] = (uint16_t)new_id;
        }
        claw_memory_adjust_summary_stats(new_index, item, 1);
    }
    claw_memory_rebuild_keyword_index(new_index, &compacted);
    claw_memory_set_index_last_compact_digest_size(new_index, digest_size);
    if (old_index && cJSON_GetObjectItem(old_index, CLAW_MEMORY_PIPELINE_KEY)) {
        cJSON_AddItemToObject(new_index, CLAW_MEMORY_PIPELINE_KEY,
                              cJSON_DetachItemFromObject(old_index, CLAW_MEMORY_PIPELINE_KEY));
    }

    err = claw_memory_records_write_snapshot(&compacted);
    if (err == ESP_OK) {
        err = claw_memory_save_index(new_index);
    }
    if (err == ESP_OK && append_digest) {
        claw_memory_append_digest_line("compact", NULL, "rebuild=index+markdown");
    }

    free(scratch_item);
    cJSON_Delete(old_index);
    cJSON_Delete(new_index);
    claw_memory_item_list_free(&items);
    claw_memory_item_list_free(&compacted);
    if (err == ESP_OK) {
        s_memory.write_changes_since_compact = 0;
    }
    return err;
}

esp_err_t claw_memory_maybe_compact(void)
{
    if (s_memory.write_changes_since_compact >= CLAW_MEMORY_COMPACT_CHANGE_THRESHOLD ||
        file_size_bytes(s_memory.records_path) >= CLAW_MEMORY_COMPACT_SIZE_THRESHOLD) {
        return claw_memory_compact_internal(true);
    }
    return ESP_OK;
}
