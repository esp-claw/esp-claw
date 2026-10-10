/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool text_contains_token(const char *haystack, const char *needle)
{
    return (haystack && needle && needle[0]) &&
           ((strstr(haystack, needle) != NULL) || text_contains_ascii_ci(haystack, needle));
}

static void claw_memory_build_semantic_key(const claw_memory_item_t *item,
                                           char *dst,
                                           size_t dst_size)
{
    if (!dst || dst_size == 0) {
        return;
    }
    dst[0] = '\0';
    normalize_text_for_key(item ? item->content : NULL, dst, dst_size);
}

bool claw_memory_items_semantically_match(const claw_memory_item_t *existing,
                                          const claw_memory_item_t *incoming)
{
    char existing_key[160];
    char incoming_key[160];
    size_t existing_len;
    size_t incoming_len;

    if (!existing || !incoming || existing->deleted) {
        return false;
    }

    claw_memory_build_semantic_key(existing, existing_key, sizeof(existing_key));
    claw_memory_build_semantic_key(incoming, incoming_key, sizeof(incoming_key));
    if (!existing_key[0] || !incoming_key[0]) {
        return false;
    }
    if (strcmp(existing_key, incoming_key) == 0) {
        return true;
    }

    existing_len = strlen(existing_key);
    incoming_len = strlen(incoming_key);
    if (existing_len >= 12 && incoming_len >= 12) {
        return strstr(existing_key, incoming_key) != NULL ||
               strstr(incoming_key, existing_key) != NULL;
    }
    return false;
}

bool claw_memory_items_equivalent_for_update(const claw_memory_item_t *existing,
                                             const claw_memory_item_t *replacement)
{
    if (!existing || !replacement) {
        return false;
    }

    return strcmp(existing->source, replacement->source) == 0 &&
           strcmp(existing->content, replacement->content) == 0 &&
           strcmp(existing->tags, replacement->tags) == 0 &&
           strcmp(existing->keywords, replacement->keywords) == 0;
}

static bool claw_memory_csv_contains_term(const char *csv_text, const char *term)
{
    char copy[160];
    char *token;
    char *saveptr = NULL;

    if (!csv_text || !csv_text[0] || !term || !term[0]) {
        return false;
    }

    safe_copy(copy, sizeof(copy), csv_text);
    token = strtok_r(copy, ",;/|", &saveptr);
    while (token) {
        trim_whitespace(token);
        if (token[0] && strcmp(token, term) == 0) {
            return true;
        }
        token = strtok_r(NULL, ",;/|", &saveptr);
    }
    return false;
}

static bool claw_memory_term_is_grounded(const char *term,
                                         const char *content,
                                         const char *tags)
{
    if (!term || !term[0]) {
        return false;
    }
    return text_contains_token(content, term) || text_contains_token(tags, term);
}

static size_t claw_memory_append_csv_terms(char *dst,
                                           size_t dst_size,
                                           size_t current_count,
                                           size_t max_terms,
                                           const char *src,
                                           const char *content,
                                           const char *tags,
                                           bool require_grounding)
{
    char copy[192];
    char *token;
    char *saveptr = NULL;

    if (!dst || dst_size == 0 || !src || !src[0] || current_count >= max_terms) {
        return current_count;
    }

    safe_copy(copy, sizeof(copy), src);
    token = strtok_r(copy, ",;/|", &saveptr);
    while (token && current_count < max_terms) {
        size_t off;
        int written;

        trim_whitespace(token);
        if (!token[0] || claw_memory_csv_contains_term(dst, token)) {
            token = strtok_r(NULL, ",;/|", &saveptr);
            continue;
        }
        if (require_grounding && !claw_memory_term_is_grounded(token, content, tags)) {
            token = strtok_r(NULL, ",;/|", &saveptr);
            continue;
        }

        off = strlen(dst);
        written = snprintf(dst + off,
                           dst_size - off,
                           "%s%s",
                           dst[0] ? "," : "",
                           token);
        if (written < 0 || (size_t)written >= dst_size - off) {
            break;
        }
        current_count++;
        token = strtok_r(NULL, ",;/|", &saveptr);
    }

    return current_count;
}

void claw_memory_normalize_item_metadata(claw_memory_item_t *item)
{
    char normalized_tags[sizeof(item->tags)] = {0};
    char normalized_keywords[sizeof(item->keywords)] = {0};
    size_t keyword_count = 0;

    if (!item) {
        return;
    }

    claw_memory_append_csv_terms(normalized_tags,
                                 sizeof(normalized_tags),
                                 0,
                                 CLAW_MEMORY_MAX_SUMMARIES,
                                 item->tags,
                                 item->content,
                                 item->tags,
                                 false);
    safe_copy(item->tags, sizeof(item->tags), normalized_tags);

    keyword_count = claw_memory_append_csv_terms(normalized_keywords,
                                                 sizeof(normalized_keywords),
                                                 0,
                                                 CLAW_MEMORY_MAX_SUMMARIES,
                                                 item->keywords,
                                                 item->content,
                                                 item->tags,
                                                 true);
    if (keyword_count < CLAW_MEMORY_MAX_SUMMARIES) {
        claw_memory_append_csv_terms(normalized_keywords,
                                     sizeof(normalized_keywords),
                                     keyword_count,
                                     CLAW_MEMORY_MAX_SUMMARIES,
                                     item->tags,
                                     item->content,
                                     item->tags,
                                     false);
    }
    safe_copy(item->keywords, sizeof(item->keywords), normalized_keywords);
}

void claw_memory_make_id(char *dst, size_t dst_size)
{
    uint32_t now = claw_memory_now_sec();

    s_memory.next_memory_seq++;
    snprintf(dst, dst_size, "mem-%" PRIu32 "-%04" PRIu32, now, s_memory.next_memory_seq % 10000);
}

void claw_memory_build_item_key(const claw_memory_item_t *item,
                                char *key,
                                size_t key_size)
{
    char normalized[160];
    char normalized_prefix[37];

    normalize_text_for_key(item ? item->content : NULL, normalized, sizeof(normalized));
    if (!normalized[0]) {
        snprintf(key, key_size, "memory-%" PRIu32, claw_memory_now_sec());
        return;
    }

    utf8_copy_chars(normalized_prefix, sizeof(normalized_prefix), normalized, 36);
    snprintf(key, key_size, "%s", normalized_prefix);
}

static bool claw_memory_label_exists(char labels[][CLAW_MEMORY_MAX_LABEL_TEXT],
                                     size_t count,
                                     const char *candidate)
{
    size_t i;

    if (!candidate || !candidate[0]) {
        return true;
    }
    for (i = 0; i < count; i++) {
        if (strcmp(labels[i], candidate) == 0) {
            return true;
        }
    }
    return false;
}

void claw_memory_collect_summary_labels(const claw_memory_item_t *item,
                                        char labels[][CLAW_MEMORY_MAX_LABEL_TEXT],
                                        size_t *label_count)
{
    size_t count = 0;
    char tag_copy[128];
    char *token;
    char *saveptr = NULL;

    if (!labels || !label_count || !item) {
        return;
    }
    *label_count = 0;

    safe_copy(tag_copy, sizeof(tag_copy), item->tags);
    token = strtok_r(tag_copy, ",;/|", &saveptr);
    while (token && count < CLAW_MEMORY_MAX_SUMMARIES) {
        char trimmed[CLAW_MEMORY_MAX_LABEL_TEXT];
        char limited[CLAW_MEMORY_MAX_LABEL_TEXT];

        safe_copy(trimmed, sizeof(trimmed), token);
        trim_whitespace(trimmed);
        utf8_copy_chars(limited, sizeof(limited), trimmed, CLAW_MEMORY_MAX_LABEL_CHARS);
        if (limited[0] && !claw_memory_label_exists(labels, count, limited)) {
            safe_copy(labels[count++], CLAW_MEMORY_MAX_LABEL_TEXT, limited);
        }
        token = strtok_r(NULL, ",;/|", &saveptr);
    }
    *label_count = count;
}

esp_err_t claw_memory_item_primary_summary_label(const claw_memory_item_t *item,
                                                 char *buf,
                                                 size_t size)
{
    char labels[CLAW_MEMORY_MAX_SUMMARIES][CLAW_MEMORY_MAX_LABEL_TEXT];
    size_t label_count = 0;

    if (!item || !buf || size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    buf[0] = '\0';
    claw_memory_collect_summary_labels(item, labels, &label_count);
    if (label_count == 0 || !labels[0][0]) {
        return ESP_ERR_NOT_FOUND;
    }

    safe_copy(buf, size, labels[0]);
    return ESP_OK;
}

cJSON *claw_memory_parse_llm_json_document(const char *text)
{
    const char *start = NULL;
    const char *end = NULL;
    char *snippet = NULL;
    cJSON *root = NULL;

    if (!text || !text[0]) {
        return NULL;
    }

    root = cJSON_Parse(text);
    if (root) {
        return root;
    }

    start = strchr(text, '{');
    end = strrchr(text, '}');
    if (start && end && end >= start) {
        size_t len = (size_t)(end - start + 1);

        snippet = calloc(1, len + 1);
        if (!snippet) {
            return NULL;
        }
        memcpy(snippet, start, len);
        root = cJSON_Parse(snippet);
        free(snippet);
        if (root) {
            return root;
        }
    }

    start = strchr(text, '[');
    end = strrchr(text, ']');
    if (start && end && end >= start) {
        size_t len = (size_t)(end - start + 1);

        snippet = calloc(1, len + 1);
        if (!snippet) {
            return NULL;
        }
        memcpy(snippet, start, len);
        root = cJSON_Parse(snippet);
        free(snippet);
    }
    return root;
}
