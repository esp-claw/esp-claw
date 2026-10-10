/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "llm/claw_llm_history.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *json_string(const cJSON *object, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);

    return cJSON_IsString(item) && item->valuestring ? item->valuestring : NULL;
}

static bool is_role(const cJSON *message, const char *role)
{
    const char *value = json_string(message, "role");

    return value && strcmp(value, role) == 0;
}

/* Collects the call ids of an assistant message (OpenAI tool_calls and Anthropic tool_use blocks). */
static size_t collect_call_ids(const cJSON *message, const char **ids)
{
    const cJSON *item;
    size_t count = 0;

    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(message, "tool_calls")) {
        const char *id = json_string(item, "id");

        if (id) {
            if (ids) {
                ids[count] = id;
            }
            count++;
        }
    }
    item = cJSON_GetObjectItemCaseSensitive(message, "content");
    if (cJSON_IsArray(item)) {
        const cJSON *block;

        cJSON_ArrayForEach(block, item) {
            const char *type = json_string(block, "type");
            const char *id = json_string(block, "id");

            if (type && strcmp(type, "tool_use") == 0 && id) {
                if (ids) {
                    ids[count] = id;
                }
                count++;
            }
        }
    }
    return count;
}

static cJSON *synthetic_output(const char *call_id)
{
    cJSON *message = cJSON_CreateObject();

    if (!message ||
            !cJSON_AddStringToObject(message, "role", "tool") ||
            !cJSON_AddStringToObject(message, "tool_call_id", call_id) ||
            !cJSON_AddStringToObject(message, "content", CLAW_LLM_HISTORY_MISSING_TOOL_RESULT) ||
            !cJSON_AddTrueToObject(message, "is_error")) {
        cJSON_Delete(message);
        return NULL;
    }
    return message;
}

bool claw_llm_history_repair_tool_pairs(cJSON *messages, claw_llm_tool_pair_repair_t *out_stats)
{
    claw_llm_tool_pair_repair_t stats = {0};
    int i = 0;
    bool ok = true;

    if (!cJSON_IsArray(messages)) {
        if (out_stats) {
            *out_stats = stats;
        }
        return true;
    }

    while (ok && i < cJSON_GetArraySize(messages)) {
        cJSON *message = cJSON_GetArrayItem(messages, i);
        size_t call_count;
        const char **ids = NULL;
        bool *matched = NULL;
        int j;
        size_t k;

        if (is_role(message, "tool")) {
            /* Not consumed by a preceding assistant tool call. */
            cJSON_DeleteItemFromArray(messages, i);
            stats.dropped_orphan_outputs++;
            continue;
        }
        call_count = is_role(message, "assistant") ? collect_call_ids(message, NULL) : 0;
        if (call_count == 0) {
            i++;
            continue;
        }

        ids = calloc(call_count, sizeof(*ids));
        matched = calloc(call_count, sizeof(*matched));
        if (!ids || !matched) {
            free(ids);
            free(matched);
            ok = false;
            break;
        }
        collect_call_ids(message, ids);

        j = i + 1;
        while (j < cJSON_GetArraySize(messages)) {
            cJSON *output = cJSON_GetArrayItem(messages, j);
            const char *call_id;
            size_t found = call_count;

            if (!is_role(output, "tool")) {
                break;
            }
            call_id = json_string(output, "tool_call_id");
            for (k = 0; call_id && k < call_count; k++) {
                if (strcmp(ids[k], call_id) == 0) {
                    found = k;
                    break;
                }
            }
            if (found == call_count) {
                cJSON_DeleteItemFromArray(messages, j);
                stats.dropped_orphan_outputs++;
            } else if (matched[found]) {
                cJSON_DeleteItemFromArray(messages, j);
                stats.dropped_duplicate_outputs++;
            } else {
                matched[found] = true;
                j++;
            }
        }
        for (k = 0; k < call_count; k++) {
            cJSON *output;

            if (matched[k]) {
                continue;
            }
            output = synthetic_output(ids[k]);
            if (!output || !cJSON_InsertItemInArray(messages, j, output)) {
                cJSON_Delete(output);
                ok = false;
                break;
            }
            stats.synthesized_outputs++;
            j++;
        }
        free(ids);
        free(matched);
        i = j;
    }

    if (out_stats) {
        *out_stats = stats;
    }
    return ok;
}

/* Length of the valid UTF-8 sequence at s, or 0 when the byte does not start one. */
static size_t utf8_valid_len(const unsigned char *s, size_t avail)
{
    size_t n;
    size_t i;

    if (s[0] < 0x80) {
        return 1;
    }
    if (s[0] >= 0xC2 && s[0] <= 0xDF) {
        n = 2;
    } else if (s[0] >= 0xE0 && s[0] <= 0xEF) {
        n = 3;
    } else if (s[0] >= 0xF0 && s[0] <= 0xF4) {
        n = 4;
    } else {
        return 0;
    }
    if (n > avail) {
        return 0;
    }
    for (i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) {
            return 0;
        }
    }
    if ((s[0] == 0xE0 && s[1] < 0xA0) || (s[0] == 0xED && s[1] > 0x9F) ||
            (s[0] == 0xF0 && s[1] < 0x90) || (s[0] == 0xF4 && s[1] > 0x8F)) {
        return 0;
    }
    return n;
}

static bool utf8_is_continuation(char c)
{
    return ((unsigned char)c & 0xC0) == 0x80;
}

bool claw_llm_history_clip_text(char *text, size_t max_bytes)
{
    char marker[48];
    size_t len;
    size_t i;
    size_t marker_max;
    size_t head;
    size_t tail_start;
    int marker_len;
    bool changed = false;

    if (!text) {
        return false;
    }
    len = strlen(text);
    for (i = 0; i < len;) {
        size_t n = utf8_valid_len((const unsigned char *)text + i, len - i);

        if (n == 0) {
            text[i++] = '?';
            changed = true;
        } else {
            i += n;
        }
    }
    if (len <= max_bytes) {
        return changed;
    }

    marker_len = snprintf(marker, sizeof(marker), "\n[... %zu bytes truncated ...]\n", len);
    marker_max = marker_len > 0 ? (size_t)marker_len : 0;
    if (max_bytes < marker_max + 16) {
        head = max_bytes;
        while (head > 0 && utf8_is_continuation(text[head])) {
            head--;
        }
        text[head] = '\0';
        return true;
    }

    head = (max_bytes - marker_max) * 2 / 3;
    tail_start = len - (max_bytes - marker_max - head);
    while (head > 0 && utf8_is_continuation(text[head])) {
        head--;
    }
    while (tail_start < len && utf8_is_continuation(text[tail_start])) {
        tail_start++;
    }
    marker_len = snprintf(marker, sizeof(marker), "\n[... %zu bytes truncated ...]\n", tail_start - head);
    if (marker_len < 0) {
        marker_len = 0;
    }
    memmove(text + head + (size_t)marker_len, text + tail_start, len - tail_start + 1);
    memcpy(text + head, marker, (size_t)marker_len);
    return true;
}
