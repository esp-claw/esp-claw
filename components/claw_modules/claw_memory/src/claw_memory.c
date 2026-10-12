/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#define CLAW_MEMORY_RECALL_MIN_MATCH 0.15f

static const char *TAG = "claw_memory";

claw_memory_state_t s_memory = {0};
static SemaphoreHandle_t s_memory_lock = NULL;

static esp_err_t claw_memory_enter_storage_degraded(const char *reason, bool repair_required)
{
    s_memory.initialized = 0;
    s_memory.storage_degraded = true;
    s_memory.storage_repair_required = repair_required;
    ESP_LOGE(TAG, "Memory storage degraded (%s); memory disabled until restart after recovery",
             reason ? reason : "storage error");
    return ESP_OK;
}

void claw_memory_lock(void)
{
    if (s_memory_lock) {
        xSemaphoreTakeRecursive(s_memory_lock, portMAX_DELAY);
    }
}

void claw_memory_unlock(void)
{
    if (s_memory_lock) {
        xSemaphoreGiveRecursive(s_memory_lock);
    }
}

/* Append a formatted chunk into buf[off..buf_size) and return the number of
 * bytes ACTUALLY written (never the snprintf "would-have-written" value), so
 * a running offset can never advance past the buffer. */
static size_t claw_memory_append(char *buf, size_t buf_size, size_t off,
                                 const char *fmt, ...)
{
    va_list ap;
    int n;

    if (!buf || off >= buf_size) {
        return 0;
    }
    va_start(ap, fmt);
    n = vsnprintf(buf + off, buf_size - off, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return 0;
    }
    if ((size_t)n >= buf_size - off) {
        return buf_size - off - 1; /* truncated: filled to the last byte */
    }
    return (size_t)n;
}

static void claw_memory_fill_defaults(claw_memory_item_t *item)
{
    if (!item) {
        return;
    }
    if (!item->source[0]) {
        safe_copy(item->source, sizeof(item->source), "manual");
    }
}

static esp_err_t claw_memory_store_prepared_item_locked(claw_memory_item_t *item,
                                                        const char *digest_action,
                                                        const char *digest_extra,
                                                        const char *ignore_existing_id,
                                                        bool *out_changed);

static esp_err_t claw_memory_store_prepared_item_internal(claw_memory_item_t *item,
                                                          const char *digest_action,
                                                          const char *digest_extra,
                                                          const char *ignore_existing_id,
                                                          bool *out_changed)
{
    esp_err_t err;

    if (!item || !item->content[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    if (out_changed) {
        *out_changed = false;
    }

    claw_memory_lock();
    err = claw_memory_store_prepared_item_locked(item, digest_action, digest_extra,
                                                 ignore_existing_id, out_changed);
    claw_memory_unlock();
    return err;
}

static esp_err_t claw_memory_store_prepared_item_locked(claw_memory_item_t *item,
                                                        const char *digest_action,
                                                        const char *digest_extra,
                                                        const char *ignore_existing_id,
                                                        bool *out_changed)
{
    claw_memory_item_list_t items = {0};
    cJSON *index_root = NULL;
    char labels[CLAW_MEMORY_MAX_SUMMARIES][CLAW_MEMORY_MAX_LABEL_TEXT];
    char item_key[48];
    size_t label_count = 0;
    size_t i;
    esp_err_t err;

    trim_whitespace(item->content);
    trim_whitespace(item->tags);
    trim_whitespace(item->keywords);
    claw_memory_normalize_item_metadata(item);
    if (!item->content[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    claw_memory_fill_defaults(item);

    if (!item->id[0]) {
        claw_memory_make_id(item->id, sizeof(item->id));
    }

    if (!item->created_at) {
        item->created_at = claw_memory_now_sec();
    }
    item->updated_at = claw_memory_now_sec();
    claw_memory_build_item_key(item, item_key, sizeof(item_key));

    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        return err;
    }
    for (i = 0; i < items.count; i++) {
        if (ignore_existing_id && ignore_existing_id[0] &&
            strcmp(items.items[i].id, ignore_existing_id) == 0) {
            continue;
        }
        if (!items.items[i].deleted) {
            char existing_key[48];

            claw_memory_build_item_key(&items.items[i], existing_key, sizeof(existing_key));
            if (existing_key[0] && strcmp(existing_key, item_key) == 0) {
                safe_copy(item->id, sizeof(item->id), items.items[i].id);
                *item = items.items[i];
                claw_memory_item_list_free(&items);
                return ESP_OK;
            }
        }
        if (claw_memory_items_semantically_match(&items.items[i], item)) {
            safe_copy(item->id, sizeof(item->id), items.items[i].id);
            *item = items.items[i];
            claw_memory_item_list_free(&items);
            return ESP_OK;
        }
    }

    err = claw_memory_load_index(&index_root);
    if (err != ESP_OK) {
        claw_memory_item_list_free(&items);
        return err;
    }

    claw_memory_collect_summary_labels(item, labels, &label_count);
    item->summary_id_count = 0;
    for (i = 0; i < label_count && i < CLAW_MEMORY_MAX_SUMMARIES; i++) {
        int summary_id = 0;

        err = claw_memory_ensure_summary_label(index_root, labels[i], 0, &summary_id);
        if (err != ESP_OK) {
            cJSON_Delete(index_root);
            claw_memory_item_list_free(&items);
            return err;
        }
        item->summary_ids[item->summary_id_count++] = (uint16_t)summary_id;
    }

    err = claw_memory_append_record(item);
    if (err == ESP_OK) {
        claw_memory_adjust_summary_stats(index_root, item, 1);
        claw_memory_item_list_push(&items, item);
        claw_memory_rebuild_keyword_index(index_root, &items);
        err = claw_memory_save_index(index_root);
    }
    if (err == ESP_OK) {
        claw_memory_append_digest_line(digest_action, item, digest_extra);
        s_memory.write_changes_since_compact++;
        if (out_changed) {
            *out_changed = true;
        }
    }

    cJSON_Delete(index_root);
    claw_memory_item_list_free(&items);
    if (err == ESP_OK) {
        err = claw_memory_maybe_compact();
    }
    return err;
}

static esp_err_t claw_memory_store_prepared_item(claw_memory_item_t *item,
                                                 const char *digest_action,
                                                 const char *digest_extra,
                                                 bool *out_changed)
{
    return claw_memory_store_prepared_item_internal(item,
                                                    digest_action,
                                                    digest_extra,
                                                    NULL,
                                                    out_changed);
}

static void claw_memory_apply_update_patch(claw_memory_item_t *dst,
                                           const claw_memory_item_t *patch)
{
    if (!dst || !patch) {
        return;
    }

    if (patch->source[0]) {
        safe_copy(dst->source, sizeof(dst->source), patch->source);
    }
    if (patch->content[0]) {
        safe_copy(dst->content, sizeof(dst->content), patch->content);
    }
    if (patch->tags[0]) {
        safe_copy(dst->tags, sizeof(dst->tags), patch->tags);
    }
    if (patch->keywords[0]) {
        safe_copy(dst->keywords, sizeof(dst->keywords), patch->keywords);
    }
    if (patch->importance) {
        dst->importance = patch->importance;
    }
    if (patch->kind) {
        dst->kind = patch->kind;
    }
}

static esp_err_t claw_memory_prepare_updated_replacement(const claw_memory_item_t *existing,
                                                         const claw_memory_item_t *patch,
                                                         claw_memory_item_t *replacement)
{
    if (!existing || !patch || !replacement) {
        return ESP_ERR_INVALID_ARG;
    }

    *replacement = *existing;
    memset(replacement->id, 0, sizeof(replacement->id));
    memset(replacement->summary_ids, 0, sizeof(replacement->summary_ids));
    replacement->summary_id_count = 0;
    replacement->deleted = 0;
    replacement->access_count = 0;
    replacement->created_at = 0;
    replacement->updated_at = 0;

    claw_memory_apply_update_patch(replacement, patch);
    trim_whitespace(replacement->content);
    trim_whitespace(replacement->tags);
    trim_whitespace(replacement->keywords);
    claw_memory_normalize_item_metadata(replacement);
    claw_memory_fill_defaults(replacement);
    if (!replacement->content[0]) {
        return ESP_ERR_INVALID_ARG;
    }
    return ESP_OK;
}

static bool claw_memory_item_matches_summary_ids(const claw_memory_item_t *item,
                                                 const int *summary_ids,
                                                 size_t summary_id_count)
{
    size_t i;
    size_t j;

    if (!item || summary_id_count == 0) {
        return true;
    }
    for (i = 0; i < summary_id_count; i++) {
        for (j = 0; j < item->summary_id_count && j < CLAW_MEMORY_MAX_SUMMARIES; j++) {
            if ((int)item->summary_ids[j] == summary_ids[i]) {
                return true;
            }
        }
    }
    return false;
}

static esp_err_t claw_memory_render_item_list_json(const claw_memory_item_list_t *items,
                                                   cJSON *index_root,
                                                   char **out_json)
{
    cJSON *array = NULL;
    char *text = NULL;
    size_t i;

    if (!out_json) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_json = NULL;

    array = cJSON_CreateArray();
    if (!array) {
        return ESP_ERR_NO_MEM;
    }

    for (i = 0; items && i < items->count; i++) {
        cJSON *json = claw_memory_item_to_json(&items->items[i], index_root);
        if (json) {
            cJSON_AddItemToArray(array, json);
        }
    }

    text = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);
    if (!text) {
        return ESP_ERR_NO_MEM;
    }
    *out_json = text;
    return ESP_OK;
}

typedef struct {
    float score;
    size_t index;
} claw_memory_ranked_t;

static int claw_memory_ranked_desc(const void *a, const void *b)
{
    const claw_memory_ranked_t *ra = (const claw_memory_ranked_t *)a;
    const claw_memory_ranked_t *rb = (const claw_memory_ranked_t *)b;

    if (ra->score != rb->score) {
        return ra->score < rb->score ? 1 : -1;
    }
    return ra->index < rb->index ? -1 : (ra->index > rb->index);
}

esp_err_t claw_memory_init(const claw_memory_config_t *config)
{
    static const char *const default_markdown =
        "# Long-term Memory\n\n"
        "(empty - ESP-Claw will write memories here as it learns)\n";
    static const char *const default_index =
        "{\"version\":3,\"next_summary_id\":1,\"last_compact_digest_size\":0,\"summaries\":[],\"keyword_index\":{}}\n";

    if (!config || !config->session_root_dir || !config->memory_root_dir ||
        !config->memory_root_dir[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!s_memory_lock) {
        s_memory_lock = xSemaphoreCreateRecursiveMutex();
        if (!s_memory_lock) {
            return ESP_ERR_NO_MEM;
        }
    }
    memset(&s_memory, 0, sizeof(s_memory));
    safe_copy(s_memory.storage_root_dir, sizeof(s_memory.storage_root_dir), config->storage_root_dir);
    safe_copy(s_memory.session_root_dir, sizeof(s_memory.session_root_dir), config->session_root_dir);
    safe_copy(s_memory.memory_root_dir,
              sizeof(s_memory.memory_root_dir),
              config->memory_root_dir);
    s_memory.max_message_chars = config->max_message_chars ?
        config->max_message_chars : CLAW_MEMORY_DEFAULT_MAX_MESSAGE_CHARS;
    s_memory.max_tool_iterations = config->max_tool_iterations ?
        config->max_tool_iterations : CLAW_MEMORY_DEFAULT_MAX_TOOL_ITERATIONS;
    s_memory.backend_format = claw_memory_backend_format_from_type(config->llm.backend_type);
    s_memory.next_memory_seq = claw_memory_now_sec() % 10000U;

    if (claw_memory_join_path(s_memory.markdown_path,
                              sizeof(s_memory.markdown_path),
                              s_memory.memory_root_dir,
                              CLAW_MEMORY_MARKDOWN_FILE) != ESP_OK ||
        claw_memory_join_path(s_memory.records_path,
                              sizeof(s_memory.records_path),
                              s_memory.memory_root_dir,
                              CLAW_MEMORY_RECORDS_FILE) != ESP_OK ||
        claw_memory_join_path(s_memory.index_path,
                              sizeof(s_memory.index_path),
                              s_memory.memory_root_dir,
                              CLAW_MEMORY_INDEX_FILE) != ESP_OK ||
        claw_memory_join_path(s_memory.digest_path,
                              sizeof(s_memory.digest_path),
                              s_memory.memory_root_dir,
                              CLAW_MEMORY_DIGEST_FILE) != ESP_OK ||
        claw_memory_join_path(s_memory.vectors_path,
                              sizeof(s_memory.vectors_path),
                              s_memory.memory_root_dir,
                              CLAW_MEMORY_VECTORS_FILE) != ESP_OK) {
        return ESP_ERR_INVALID_SIZE;
    }

    if (ensure_dir_recursive(s_memory.session_root_dir) != ESP_OK ||
        ensure_dir_recursive(s_memory.memory_root_dir) != ESP_OK) {
        return claw_memory_enter_storage_degraded("directory setup failed", false);
    }

    /* Recover interrupted atomic replacements before defaults can create an
     * empty primary that would hide a valid transaction sidecar. */
    {
        esp_err_t err = claw_memory_records_prepare_for_default();

        if (err == ESP_OK) {
            err = claw_memory_index_prepare_for_default();
        }
        if (err != ESP_OK) {
            return claw_memory_enter_storage_degraded(
                "interrupted files could not be recovered", err == ESP_ERR_INVALID_STATE);
        }
    }
    if (claw_memory_profile_init_defaults() != ESP_OK) {
        return claw_memory_enter_storage_degraded("profile defaults unavailable", false);
    }
    if (ensure_file_with_default(s_memory.records_path, "") != ESP_OK ||
        ensure_file_with_default(s_memory.index_path, default_index) != ESP_OK ||
        ensure_file_with_default(s_memory.digest_path, "") != ESP_OK ||
        ensure_file_with_default(s_memory.markdown_path, default_markdown) != ESP_OK) {
        return claw_memory_enter_storage_degraded("memory defaults unavailable", false);
    }

    {
        esp_err_t err = claw_memory_compact_internal(false);

        if (err != ESP_OK) {
            return claw_memory_enter_storage_degraded("memory files failed validation",
                                                       err == ESP_ERR_INVALID_STATE);
        }
    }
    s_memory.initialized = 1;
    {
        esp_err_t err = claw_memory_embed_init(&config->embed);

        if (err == ESP_OK) {
            err = claw_memory_pipeline_init(config);
        }
        if (err != ESP_OK) {
            return err;
        }
    }
    ESP_LOGI(TAG, "Initialized memory root=%s", s_memory.memory_root_dir);
    return ESP_OK;
}

esp_err_t claw_memory_store(const claw_memory_item_t *item)
{
    claw_memory_item_t *prepared = NULL;
    esp_err_t err;

    if (!s_memory.initialized || !item) {
        return ESP_ERR_INVALID_STATE;
    }
    prepared = calloc(1, sizeof(*prepared));
    if (!prepared) {
        return ESP_ERR_NO_MEM;
    }
    *prepared = *item;
    err = claw_memory_store_prepared_item(prepared, "store", NULL, NULL);
    free(prepared);
    return err;
}

esp_err_t claw_memory_store_with_result(claw_memory_item_t *item, bool *out_changed)
{
    if (!s_memory.initialized || !item) {
        return ESP_ERR_INVALID_STATE;
    }

    return claw_memory_store_prepared_item(item, "store", NULL, out_changed);
}

esp_err_t claw_memory_recall(const claw_memory_query_t *query, char **out_json)
{
    char tokens[CLAW_MEMORY_QUERY_MAX_TOKENS][CLAW_MEMORY_TOKEN_MAX];
    claw_memory_item_list_t items = {0};
    claw_memory_item_list_t matches = {0};
    claw_memory_ranked_t *ranked = NULL;
    cJSON *index_root = NULL;
    float *query_vec = NULL;
    int summary_ids[CLAW_MEMORY_MAX_SUMMARIES] = {0};
    size_t resolved_summary_count = 0;
    size_t token_count = 0;
    size_t ranked_count = 0;
    size_t limit;
    size_t i;
    bool has_query = false;
    bool has_query_vec = false;
    uint32_t now = claw_memory_now_sec();
    esp_err_t err;

    if (!query || !out_json) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_memory.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (query->query && query->query[0]) {
        token_count = claw_memory_tokenize(query->query, tokens, CLAW_MEMORY_QUERY_MAX_TOKENS);
        if (claw_memory_embed_enabled() && !claw_memory_text_has_secret(query->query)) {
            query_vec = malloc(CLAW_MEMORY_EMBED_DIM * sizeof(float));
            has_query_vec = query_vec && claw_memory_embed_query(query->query, query_vec) == ESP_OK;
        }
        /* A query made only of stop words ranks like no query at all. */
        has_query = token_count > 0 || has_query_vec;
    }

    claw_memory_lock();
    err = claw_memory_load_index(&index_root);
    if (err != ESP_OK) {
        goto cleanup;
    }
    for (i = 0; i < query->summary_label_count && i < CLAW_MEMORY_MAX_SUMMARIES; i++) {
        cJSON *summary = claw_memory_find_summary_by_label(index_root, query->summary_labels[i]);
        if (summary) {
            summary_ids[resolved_summary_count++] =
                cJSON_GetObjectItem(summary, "summary_id")->valueint;
        }
    }
    if (query->summary_label_count > 0 && resolved_summary_count == 0) {
        err = claw_memory_render_item_list_json(NULL, index_root, out_json);
        goto cleanup;
    }

    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        goto cleanup;
    }
    ranked = calloc(items.count ? items.count : 1, sizeof(*ranked));
    if (!ranked) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    for (i = 0; i < items.count; i++) {
        const claw_memory_item_t *item = &items.items[i];
        float match = 1.0f;

        if (item->deleted ||
            !claw_memory_item_matches_summary_ids(item, summary_ids, resolved_summary_count)) {
            continue;
        }
        if (has_query) {
            const int8_t *vec = has_query_vec ? claw_memory_vectors_get(item->id) : NULL;
            float keyword = claw_memory_keyword_match(tokens, token_count, item->content,
                                                      item->tags, item->keywords);

            match = claw_memory_hybrid_match(vec ? claw_memory_vec_cosine(vec, query_vec) : 0.0f,
                                             keyword, vec != NULL);
            if (match < CLAW_MEMORY_RECALL_MIN_MATCH) {
                continue;
            }
        }
        ranked[ranked_count].score = claw_memory_rank_score(match, now, item->updated_at,
                                                            item->access_count, item->importance);
        ranked[ranked_count++].index = i;
    }
    qsort(ranked, ranked_count, sizeof(*ranked), claw_memory_ranked_desc);

    limit = query->limit ? query->limit : CLAW_MEMORY_RECALL_DEFAULT_LIMIT;
    for (i = 0; i < ranked_count && i < limit; i++) {
        err = claw_memory_item_list_push(&matches, &items.items[ranked[i].index]);
        if (err != ESP_OK) {
            goto cleanup;
        }
    }

    err = claw_memory_render_item_list_json(&matches, index_root, out_json);
    for (i = 0; err == ESP_OK && i < matches.count; i++) {
        claw_memory_pipeline_note_access(matches.items[i].id);
    }

cleanup:
    claw_memory_unlock();
    cJSON_Delete(index_root);
    claw_memory_item_list_free(&items);
    claw_memory_item_list_free(&matches);
    free(ranked);
    free(query_vec);
    return err;
}

esp_err_t claw_memory_update(const claw_memory_item_t *item)
{
    claw_memory_item_t *updated_item = NULL;
    esp_err_t err;

    if (!item) {
        return ESP_ERR_INVALID_ARG;
    }

    updated_item = calloc(1, sizeof(*updated_item));
    if (!updated_item) {
        return ESP_ERR_NO_MEM;
    }
    *updated_item = *item;
    err = claw_memory_update_with_result(updated_item, NULL);
    free(updated_item);
    return err;
}

static esp_err_t claw_memory_update_locked(claw_memory_item_t *item, bool *out_changed);

esp_err_t claw_memory_update_with_result(claw_memory_item_t *item, bool *out_changed)
{
    esp_err_t err;

    claw_memory_lock();
    err = claw_memory_update_locked(item, out_changed);
    claw_memory_unlock();
    return err;
}

static esp_err_t claw_memory_update_locked(claw_memory_item_t *item, bool *out_changed)
{
    claw_memory_item_list_t items = {0};
    claw_memory_item_t *replacement = NULL;
    claw_memory_item_t *forgotten = NULL;
    bool stored_changed = false;
    bool forgotten_changed = false;
    int idx;
    esp_err_t err;

    if (!item || !item->id[0]) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_memory.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (out_changed) {
        *out_changed = false;
    }

    replacement = calloc(1, sizeof(*replacement));
    forgotten = calloc(1, sizeof(*forgotten));
    if (!replacement || !forgotten) {
        free(replacement);
        free(forgotten);
        return ESP_ERR_NO_MEM;
    }

    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        free(replacement);
        free(forgotten);
        return err;
    }
    idx = claw_memory_find_item_index(&items, item->id);
    if (idx < 0 || items.items[idx].deleted) {
        claw_memory_item_list_free(&items);
        free(replacement);
        free(forgotten);
        return ESP_ERR_NOT_FOUND;
    }

    err = claw_memory_prepare_updated_replacement(&items.items[idx], item, replacement);
    if (err == ESP_OK &&
        claw_memory_items_equivalent_for_update(&items.items[idx], replacement)) {
        *item = items.items[idx];
        claw_memory_item_list_free(&items);
        free(replacement);
        free(forgotten);
        return ESP_OK;
    }
    claw_memory_item_list_free(&items);
    if (err != ESP_OK) {
        free(replacement);
        free(forgotten);
        return err;
    }

    err = claw_memory_store_prepared_item_internal(replacement,
                                                   "update_store",
                                                   item->id,
                                                   item->id,
                                                   &stored_changed);
    if (err != ESP_OK) {
        free(replacement);
        free(forgotten);
        return err;
    }

    err = claw_memory_forget_with_result(item->id, forgotten, &forgotten_changed);
    if (err != ESP_OK) {
        free(replacement);
        free(forgotten);
        return err;
    }

    claw_memory_append_digest_line("update", replacement, forgotten->id);
    *item = *replacement;
    if (out_changed) {
        *out_changed = stored_changed || forgotten_changed;
    }

    err = claw_memory_maybe_compact();
    free(replacement);
    free(forgotten);
    return err;
}

esp_err_t claw_memory_forget(const char *memory_id)
{
    return claw_memory_forget_with_result(memory_id, NULL, NULL);
}

static esp_err_t claw_memory_forget_locked(const char *memory_id,
                                           claw_memory_item_t *out_item,
                                           bool *out_changed);

esp_err_t claw_memory_forget_with_result(const char *memory_id,
                                         claw_memory_item_t *out_item,
                                         bool *out_changed)
{
    esp_err_t err;

    claw_memory_lock();
    err = claw_memory_forget_locked(memory_id, out_item, out_changed);
    claw_memory_unlock();
    return err;
}

static esp_err_t claw_memory_forget_locked(const char *memory_id,
                                           claw_memory_item_t *out_item,
                                           bool *out_changed)
{
    claw_memory_item_list_t items = {0};
    cJSON *index_root = NULL;
    claw_memory_item_t *forgotten = NULL;
    int idx;
    esp_err_t err;

    if (!memory_id || !memory_id[0]) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_memory.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    if (out_changed) {
        *out_changed = false;
    }

    forgotten = calloc(1, sizeof(*forgotten));
    if (!forgotten) {
        return ESP_ERR_NO_MEM;
    }

    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        free(forgotten);
        return err;
    }
    idx = claw_memory_find_item_index(&items, memory_id);
    if (idx < 0 || items.items[idx].deleted) {
        claw_memory_item_list_free(&items);
        free(forgotten);
        return ESP_ERR_NOT_FOUND;
    }

    *forgotten = items.items[idx];
    forgotten->deleted = 1;
    forgotten->updated_at = claw_memory_now_sec();
    if (out_item) {
        *out_item = items.items[idx];
    }

    err = claw_memory_append_record(forgotten);
    if (err != ESP_OK) {
        claw_memory_item_list_free(&items);
        free(forgotten);
        return err;
    }

    err = claw_memory_load_index(&index_root);
    if (err != ESP_OK) {
        claw_memory_item_list_free(&items);
        free(forgotten);
        return err;
    }

    items.items[idx] = *forgotten;
    claw_memory_adjust_summary_stats(index_root, forgotten, -1);
    claw_memory_remove_unused_summaries(index_root);
    claw_memory_rebuild_keyword_index(index_root, &items);
    err = claw_memory_save_index(index_root);
    if (err == ESP_OK) {
        claw_memory_vectors_remove(memory_id);
        claw_memory_append_digest_line("forget", forgotten, NULL);
        s_memory.write_changes_since_compact++;
        if (out_changed) {
            *out_changed = true;
        }
    }

    cJSON_Delete(index_root);
    claw_memory_item_list_free(&items);
    if (err == ESP_OK) {
        err = claw_memory_maybe_compact();
    }
    free(forgotten);
    return err;
}

esp_err_t claw_memory_list(char **out_json)
{
    claw_memory_item_list_t items = {0};
    claw_memory_item_list_t filtered = {0};
    cJSON *index_root = NULL;
    size_t i;
    esp_err_t err;

    if (!out_json) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_memory.initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    claw_memory_lock();
    err = claw_memory_load_current_items(&items);
    if (err != ESP_OK) {
        claw_memory_unlock();
        return err;
    }
    for (i = 0; i < items.count; i++) {
        if (items.items[i].deleted) {
            continue;
        }
        if (claw_memory_item_list_push(&filtered, &items.items[i]) != ESP_OK) {
            claw_memory_unlock();
            claw_memory_item_list_free(&items);
            claw_memory_item_list_free(&filtered);
            return ESP_ERR_NO_MEM;
        }
    }
    if (filtered.count > 1) {
        qsort(filtered.items, filtered.count, sizeof(*filtered.items), claw_memory_sort_by_priority_desc);
    }

    err = claw_memory_load_index(&index_root);
    if (err == ESP_OK) {
        err = claw_memory_render_item_list_json(&filtered, index_root, out_json);
    }
    claw_memory_unlock();

    cJSON_Delete(index_root);
    claw_memory_item_list_free(&items);
    claw_memory_item_list_free(&filtered);
    return err;
}

static esp_err_t claw_memory_long_term_collect(const claw_core_request_t *request,
                                               claw_core_context_t *out_context,
                                               void *user_ctx)
{
    static const char k_long_term_preamble[] =
        "Long-term memory has two parts: a consolidated summary (below, rewritten nightly from the stored memories) and the stored memory items, which are not injected.\n"
        "Call memory_recall with a free-text query (and/or exact summary labels from the catalog) when you need details, exact memory_id values, or facts that are not in the summary.\n"
        "Summary labels must be copied verbatim from the catalog below. Do not invent new labels.\n"
        "If the user asks what you remember about them, what they like or prefer, or asks you to verify a remembered fact, call memory_recall before answering unless the summary already answers it.\n"
        "If the user asks you to forget a remembered item, first inspect memory_id with memory_recall or memory_list, then call memory_forget with that exact memory_id.\n"
        "If the user asks you to update a remembered item, call memory_recall to inspect the original memory bodies and memory_id values, then call memory_update with the selected memory_id.\n"
        "Do not rely on session history alone for those recall questions, because long-term memory may contain additional facts not visible in the recent chat.\n"
        "Do not mention internal memory policy, storage behavior, auto-extraction, or whether you will or will not remember something unless the user explicitly asks about memory behavior.\n"
        "Summary label catalog:\n";

    cJSON *index_root = NULL;
    cJSON *summaries;
    cJSON *item;
    char *markdown = NULL;
    size_t count = 0;
    size_t markdown_len = 0;
    size_t buf_size;
    size_t off = 0;
    char *content;
    esp_err_t err;

    (void)request;
    (void)user_ctx;

    if (!out_context) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_memory.initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    memset(out_context, 0, sizeof(*out_context));

    claw_memory_lock();
    err = claw_memory_load_index(&index_root);
    if (err == ESP_OK && read_file_dup(s_memory.markdown_path, &markdown) == ESP_OK) {
        trim_whitespace(markdown);
        markdown_len = strlen(markdown);
        if (markdown_len > CLAW_MEMORY_MARKDOWN_MAX) {
            markdown_len = CLAW_MEMORY_MARKDOWN_MAX;
            while (markdown_len > 0 && ((unsigned char)markdown[markdown_len] & 0xC0) == 0x80) {
                markdown_len--;
            }
        }
    }
    claw_memory_unlock();
    if (err != ESP_OK) {
        free(markdown);
        return err;
    }

    summaries = cJSON_GetObjectItem(index_root, "summaries");
    if (cJSON_IsArray(summaries)) {
        count = (size_t)cJSON_GetArraySize(summaries);
    }

    /* Size for the full preamble plus one line per label (labels are bounded,
     * long ones are truncated by the per-line snprintf below) and the
     * consolidated summary (capped). */
    buf_size = sizeof(k_long_term_preamble) + 96 + (count * 128) + markdown_len;
    content = calloc(1, buf_size);
    if (!content) {
        cJSON_Delete(index_root);
        free(markdown);
        return ESP_ERR_NO_MEM;
    }

    off += claw_memory_append(content, buf_size, off, "%s", k_long_term_preamble);
    cJSON_ArrayForEach(item, summaries) {
        const char *label = cJSON_GetStringValue(cJSON_GetObjectItem(item, "label"));

        if (off + 32 + markdown_len >= buf_size) {
            break;
        }
        if (!label) {
            continue;
        }
        off += claw_memory_append(content, buf_size, off, "- %s\n", label);
    }
    if (count == 0) {
        off += claw_memory_append(content, buf_size, off, "- (empty)\n");
    }
    if (markdown_len > 0) {
        off += claw_memory_append(content, buf_size, off, "\nConsolidated long-term memory (MEMORY.md):\n%.*s\n",
                                  (int)markdown_len, markdown);
    }

    out_context->kind = CLAW_CORE_CONTEXT_KIND_SYSTEM_PROMPT;
    out_context->content = content;

    cJSON_Delete(index_root);
    free(markdown);
    return ESP_OK;
}

const claw_core_context_provider_t claw_memory_long_term_provider = {
    .name = "Long-term Memory",
    .collect = claw_memory_long_term_collect,
    .user_ctx = NULL,
};
