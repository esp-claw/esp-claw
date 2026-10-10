/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Background memory pipeline, run by one worker task:
 *  - session extraction (stage 1): transcript since the per-session watermark
 *    -> durable facts + session summary, when a chat session went idle, when
 *    another session became active, or on demand;
 *  - reconcile before store (Mem0): ADD / UPDATE / DELETE / NOOP per fact;
 *  - nightly consolidation (stage 2): rewrites user.md and MEMORY.md;
 *  - batched access-count flushes, vector backfill and session storage GC.
 * LLM and HTTP calls never run with the memory lock held. */

#include "claw_memory_internal.h"
#include "claw_session_mgr.h"
#include "claw_task.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define PIPE_STACK_SIZE          (16 * 1024)
#define PIPE_PRIORITY            4
#define PIPE_TICK_MS             60000
#define PIPE_IDLE_SEC            600
#define PIPE_RETRY_SEC           600
#define PIPE_BOOT_DELAY_SEC      120
#define PIPE_TRANSCRIPT_MAX      8192
#define PIPE_TRACKED_MAX         8
#define PIPE_ACCESS_MAX          32
#define PIPE_ACCESS_FLUSH_SEC    600
#define PIPE_CONSOLIDATE_FACTS   20
#define PIPE_CONSOLIDATE_MINUTE  (3 * 60 + 30)
#define PIPE_SUMMARY_MAX_CHARS   300
#define PIPE_SUMMARIES_MAX       12
#define PIPE_WATERMARKS_MAX      48
#define PIPE_RECORDS_TEXT_MAX    6144
#define PIPE_GC_SESSIONS_MAX     64
#define PIPE_GC_EXTRACT_PER_RUN  3
#define PIPE_GC_RECENT_SEC       3600
#define PIPE_DAV_TMP_AGE_SEC     3600
#define PIPE_NEIGHBOR_MIN_COS    0.4f
#define PIPE_NEIGHBOR_MIN_KW     0.25f

static const char *TAG = "claw_memory";

static const char k_extract_prompt[] =
    "You maintain the long-term memory of a personal assistant that runs on an ESP32 device. "
    "You get a chat transcript between the user and the assistant (tool results are abbreviated). "
    "Extract durable facts about the user that will still matter in future conversations: identity and profile "
    "(name, home city, job, languages), preferences (communication style, reply language, likes and dislikes), "
    "devices and infrastructure they own or run (host names, computers, servers, smart-home devices and what they are used for), "
    "ongoing projects and goals, and important events with dates.\n"
    "Rules:\n"
    "- Only facts the user stated or confirmed, or that tool results established about the user's own devices. "
    "Never facts about the assistant, its persona, or general world knowledge.\n"
    "- Skip small talk, one-off requests, transient states and anything only the assistant claimed.\n"
    "- NEVER include secrets: passwords, API keys, tokens, PINs, private keys, credentials or account numbers.\n"
    "- Each fact is one self-contained sentence of at most 256 characters in the third person "
    "(\"The user ...\" / \"Der Nutzer ...\"), in the language the user mostly writes in.\n"
    "- tags: 1-2 short stable topic labels (e.g. location, devices, language_preference). "
    "keywords: 1-3 exact words from the fact (names, host names, places).\n"
    "- importance: 5 = core identity or standing preference, 3 = useful detail, 1 = minor.\n"
    "- kind: profile | preference | device | project | event | other.\n"
    "- At most 8 facts; an empty list when nothing durable was said.\n"
    "- session_summary: what this part of the conversation was about, at most 300 characters, no secrets.\n"
    "Respond with JSON only: {\"facts\":[{\"content\":\"...\",\"tags\":[\"...\"],\"keywords\":[\"...\"],"
    "\"importance\":3,\"kind\":\"profile\"}],\"session_summary\":\"...\"}";

static const char k_reconcile_prompt[] =
    "You reconcile new memory candidates with the existing long-term memories of a personal assistant. "
    "Decide exactly one action per candidate:\n"
    "- ADD: new information not covered by the listed existing memories.\n"
    "- UPDATE: refines, extends or corrects one existing memory about the same subject. Give its id and the merged "
    "content (one sentence, at most 256 characters, newest information wins).\n"
    "- DELETE: the candidate shows that an existing memory is obsolete or contradicted and is not worth storing "
    "itself (e.g. \"no longer owns X\"). Give the id to delete.\n"
    "- NOOP: already covered by an existing memory.\n"
    "Only use ids listed for that candidate. Never put secrets into content.\n"
    "Respond with JSON only: {\"decisions\":[{\"index\":0,\"action\":\"ADD|UPDATE|DELETE|NOOP\","
    "\"id\":\"\",\"content\":\"\"}]}";

static const char k_consolidate_prompt[] =
    "You consolidate the long-term memory of a personal assistant into two short Markdown documents that are "
    "injected into every future conversation.\n"
    "1. user_md (at most 1800 characters): who the user is - name, location, languages, communication preferences, "
    "devices and servers with their purpose, standing instructions. Keep manually written standing guidance from the "
    "current user.md unless the memories contradict it.\n"
    "2. memory_md (at most 3800 characters): other durable knowledge - projects, goals, important events with dates - "
    "and a short 'Recent sessions' list from the session summaries, newest first.\n"
    "Use concise bullet points, newest information wins on conflicts, merge duplicates, drop trivia. "
    "Never include secrets (passwords, API keys, tokens, PINs). "
    "Write in the language most memories are written in.\n"
    "Respond with JSON only: {\"user_md\":\"# User\\n...\",\"memory_md\":\"# Long-term Memory\\n...\"}";

typedef struct {
    char path[CLAW_MEMORY_MAX_PATH];
    uint32_t last_activity;
    uint32_t last_attempt;
    bool pending;
    bool force;
} pipe_tracked_t;

typedef struct {
    char id[CLAW_MEMORY_ID_MAX];
    uint16_t count;
} pipe_access_t;

static struct {
    TaskHandle_t task;
    claw_llm_runtime_t *runtime;
    pipe_tracked_t tracked[PIPE_TRACKED_MAX];
    pipe_access_t access[PIPE_ACCESS_MAX];
    size_t access_count;
    uint32_t last_access_flush;
    bool consolidate_requested;
    bool boot_done;
} s_pipe;

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} pipe_text_t;

static uint32_t pipe_uptime_sec(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000LL);
}

static bool pipe_clock_valid(uint32_t now)
{
    return now >= CLAW_MEMORY_MIN_VALID_EPOCH;
}

static const char *pipe_basename(const char *path)
{
    const char *slash = path ? strrchr(path, '/') : NULL;

    return slash ? slash + 1 : (path ? path : "");
}

static void pipe_format_date(uint32_t ts, char *buf, size_t size)
{
    time_t raw = (time_t)ts;
    struct tm tm_info;

    if (!pipe_clock_valid(ts) || !localtime_r(&raw, &tm_info) ||
        strftime(buf, size, "%Y-%m-%d", &tm_info) == 0) {
        safe_copy(buf, size, "-");
    }
}

static void pipe_text_appendf(pipe_text_t *text, const char *fmt, ...)
{
    va_list ap;
    int needed;

    va_start(ap, fmt);
    needed = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (needed < 0) {
        return;
    }
    if (text->len + (size_t)needed + 1 > text->cap) {
        size_t cap = (text->len + (size_t)needed + 1) * 2;
        char *grown = realloc(text->buf, cap);

        if (!grown) {
            return;
        }
        text->buf = grown;
        text->cap = cap;
    }
    va_start(ap, fmt);
    vsnprintf(text->buf + text->len, text->cap - text->len, fmt, ap);
    va_end(ap);
    text->len += (size_t)needed;
}

static bool pipe_is_chat_session(const char *session_id)
{
    if (!session_id || strstr(session_id, ":subagent_")) {
        return false;
    }
    return strncmp(session_id, "chat:", 5) == 0 ||
           (strncmp(session_id, "agent:", 6) == 0 && strstr(session_id, ":chat:") != NULL);
}

static bool pipe_is_chat_file(const char *basename)
{
    return strncmp(basename, "s_chat_", 7) == 0 ||
           (strncmp(basename, "s_agent_", 8) == 0 && strstr(basename, "_chat_") != NULL);
}

/* ---- persisted pipeline state in memory_index.json (lock held) ---- */

static cJSON *pipe_state_child(cJSON *state, const char *key, bool array)
{
    cJSON *child = cJSON_GetObjectItem(state, key);

    if (array ? !cJSON_IsArray(child) : !cJSON_IsObject(child)) {
        cJSON_DeleteItemFromObject(state, key);
        child = array ? cJSON_AddArrayToObject(state, key) : cJSON_AddObjectToObject(state, key);
    }
    return child;
}

static uint32_t pipe_state_number(cJSON *state, const char *key)
{
    return (uint32_t)cJSON_GetNumberValue(cJSON_GetObjectItem(state, key));
}

static void pipe_state_set_number(cJSON *state, const char *key, double value)
{
    cJSON_DeleteItemFromObject(state, key);
    cJSON_AddNumberToObject(state, key, value);
}

static cJSON *pipe_watermark(cJSON *state, const char *path)
{
    return cJSON_GetObjectItem(pipe_state_child(state, "watermarks", false), pipe_basename(path));
}

static void pipe_set_watermark(cJSON *state, const char *path, uint32_t turns)
{
    cJSON *marks = pipe_state_child(state, "watermarks", false);
    cJSON *entry = cJSON_CreateObject();

    cJSON_AddNumberToObject(entry, "n", turns);
    cJSON_AddNumberToObject(entry, "t", claw_memory_now_sec());
    cJSON_DeleteItemFromObject(marks, pipe_basename(path));
    cJSON_AddItemToObject(marks, pipe_basename(path), entry);
    while (cJSON_GetArraySize(marks) > PIPE_WATERMARKS_MAX) {
        cJSON *oldest = NULL;
        cJSON *it;

        cJSON_ArrayForEach(it, marks) {
            if (!oldest || pipe_state_number(it, "t") < pipe_state_number(oldest, "t")) {
                oldest = it;
            }
        }
        cJSON_Delete(cJSON_DetachItemViaPointer(marks, oldest));
    }
}

static void pipe_add_summary(cJSON *state, const char *path, const char *summary)
{
    cJSON *list = pipe_state_child(state, "summaries", true);
    cJSON *entry;

    if (!summary || !summary[0]) {
        return;
    }
    entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "f", pipe_basename(path));
    cJSON_AddNumberToObject(entry, "t", claw_memory_now_sec());
    cJSON_AddStringToObject(entry, "s", summary);
    cJSON_AddItemToArray(list, entry);
    while (cJSON_GetArraySize(list) > PIPE_SUMMARIES_MAX) {
        cJSON_DeleteItemFromArray(list, 0);
    }
}

/* ---- hooks called by the rest of the module (lock held) ---- */

static pipe_tracked_t *pipe_track(const char *path)
{
    pipe_tracked_t *slot = NULL;
    size_t i;

    for (i = 0; i < PIPE_TRACKED_MAX; i++) {
        if (strcmp(s_pipe.tracked[i].path, path) == 0) {
            return &s_pipe.tracked[i];
        }
        if (!slot || (!s_pipe.tracked[i].path[0] && slot->path[0]) ||
            (s_pipe.tracked[i].path[0] && slot->path[0] &&
             s_pipe.tracked[i].last_activity < slot->last_activity)) {
            slot = &s_pipe.tracked[i];
        }
    }
    /* An evicted session that still has new messages is picked up by the GC scan. */
    memset(slot, 0, sizeof(*slot));
    safe_copy(slot->path, sizeof(slot->path), path);
    return slot;
}

void claw_memory_pipeline_note_persist(const char *session_id, const char *data_path)
{
    pipe_tracked_t *tracked;

    if (!s_pipe.task || !data_path || !pipe_is_chat_session(session_id)) {
        return;
    }
    tracked = pipe_track(data_path);
    tracked->pending = true;
    tracked->last_activity = pipe_uptime_sec();
    if (file_size_bytes(data_path) > CLAW_MEMORY_GC_COMPACT_BYTES && !tracked->force) {
        tracked->force = true;
        xTaskNotifyGive(s_pipe.task);
    }
}

void claw_memory_pipeline_note_request(const char *session_id)
{
    char *path;
    bool switched = false;
    size_t i;

    if (!s_pipe.task || !pipe_is_chat_session(session_id)) {
        return;
    }
    path = claw_memory_session_path_dup(session_id);
    /* Another chat session became active: treat pending ones as ended. */
    for (i = 0; path && i < PIPE_TRACKED_MAX; i++) {
        if (s_pipe.tracked[i].pending && strcmp(s_pipe.tracked[i].path, path) != 0) {
            s_pipe.tracked[i].force = true;
            switched = true;
        }
    }
    free(path);
    if (switched) {
        xTaskNotifyGive(s_pipe.task);
    }
}

void claw_memory_pipeline_note_access(const char *memory_id)
{
    size_t i;

    for (i = 0; i < s_pipe.access_count; i++) {
        if (strcmp(s_pipe.access[i].id, memory_id) == 0) {
            if (s_pipe.access[i].count < UINT16_MAX) {
                s_pipe.access[i].count++;
            }
            return;
        }
    }
    if (s_pipe.access_count < PIPE_ACCESS_MAX) {
        safe_copy(s_pipe.access[s_pipe.access_count].id, sizeof(s_pipe.access[0].id), memory_id);
        s_pipe.access[s_pipe.access_count++].count = 1;
    }
}

esp_err_t claw_memory_request_sync(const char *session_id, bool consolidate)
{
    char *path = NULL;

    if (!s_pipe.task) {
        return ESP_ERR_INVALID_STATE;
    }
    if (session_id && session_id[0]) {
        path = claw_memory_session_path_dup(session_id);
        if (!path) {
            return ESP_ERR_NO_MEM;
        }
    }
    claw_memory_lock();
    if (path) {
        pipe_tracked_t *tracked = pipe_track(path);

        tracked->pending = true;
        tracked->force = true;
    }
    s_pipe.consolidate_requested |= consolidate;
    claw_memory_unlock();
    free(path);
    xTaskNotifyGive(s_pipe.task);
    return ESP_OK;
}

/* Lock held. Appends pending recall hits to the digest log in one write. */
static void pipe_flush_access(void)
{
    const char *ids[PIPE_ACCESS_MAX];
    uint16_t counts[PIPE_ACCESS_MAX];
    size_t i;

    for (i = 0; i < s_pipe.access_count; i++) {
        ids[i] = s_pipe.access[i].id;
        counts[i] = s_pipe.access[i].count;
    }
    if (s_pipe.access_count && claw_memory_append_recall_deltas(ids, counts, s_pipe.access_count) == ESP_OK) {
        s_pipe.access_count = 0;
    }
    s_pipe.last_access_flush = pipe_uptime_sec();
}

/* ---- LLM ---- */

static esp_err_t pipe_llm_json(const char *system_prompt, const char *user_text, cJSON **out_root)
{
    claw_llm_response_t response = {0};
    cJSON *messages = NULL;
    cJSON *user_msg = NULL;
    char *error_message = NULL;
    esp_err_t err;

    *out_root = NULL;
    if (!s_pipe.runtime) {
        return ESP_ERR_INVALID_STATE;
    }
    messages = cJSON_CreateArray();
    user_msg = cJSON_CreateObject();
    if (!messages || !user_msg) {
        cJSON_Delete(messages);
        cJSON_Delete(user_msg);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(user_msg, "role", "user");
    cJSON_AddStringToObject(user_msg, "content", user_text);
    cJSON_AddItemToArray(messages, user_msg);

    err = claw_llm_runtime_chat(s_pipe.runtime,
                                &(claw_llm_chat_request_t) {
                                    .system_prompt = system_prompt,
                                    .messages = messages,
                                    .tools_json = NULL,
                                },
                                &response,
                                &error_message);
    cJSON_Delete(messages);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "memory llm call failed: %s", error_message ? error_message : esp_err_to_name(err));
    } else {
        *out_root = claw_memory_parse_llm_json_document(response.text);
        if (!*out_root) {
            ESP_LOGW(TAG, "memory llm returned no JSON (%u bytes)",
                     (unsigned)(response.text ? strlen(response.text) : 0));
            err = ESP_ERR_INVALID_RESPONSE;
        }
    }
    free(error_message);
    claw_llm_response_free(&response);
    return err;
}

/* ---- vectors ---- */

static void pipe_backfill_vectors(void)
{
    claw_memory_item_list_t items = {0};
    const char *texts[64];
    char (*ids)[CLAW_MEMORY_ID_MAX] = NULL;
    char (*contents)[256] = NULL;
    float *vecs = NULL;
    size_t count = 0;
    size_t pruned = 0;
    size_t i;

    if (!claw_memory_embed_enabled()) {
        return;
    }
    ids = calloc(64, sizeof(*ids));
    contents = calloc(64, sizeof(*contents));
    if (!ids || !contents) {
        goto cleanup;
    }
    claw_memory_lock();
    if (claw_memory_load_current_items(&items) == ESP_OK) {
        pruned = claw_memory_vectors_prune(&items);
        for (i = 0; i < items.count && count < 64; i++) {
            const claw_memory_item_t *item = &items.items[i];

            if (item->deleted || strlen(item->id) >= 24 || claw_memory_vectors_get(item->id) ||
                claw_memory_text_has_secret(item->content)) {
                continue;
            }
            safe_copy(ids[count], sizeof(ids[count]), item->id);
            safe_copy(contents[count], sizeof(contents[count]), item->content);
            texts[count] = contents[count];
            count++;
        }
    }
    claw_memory_unlock();
    if (count == 0) {
        goto cleanup;
    }
    vecs = heap_caps_malloc(count * CLAW_MEMORY_EMBED_DIM * sizeof(float), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!vecs || claw_memory_embed_texts(texts, count, vecs) != ESP_OK) {
        goto cleanup;
    }
    claw_memory_lock();
    for (i = 0; i < count; i++) {
        (void)claw_memory_vectors_put(ids[i], vecs + i * CLAW_MEMORY_EMBED_DIM);
    }
    claw_memory_unlock();
    ESP_LOGI(TAG, "memory vectors backfilled=%u pruned=%u", (unsigned)count, (unsigned)pruned);

cleanup:
    claw_memory_item_list_free(&items);
    heap_caps_free(vecs);
    free(ids);
    free(contents);
}

/* ---- reconcile (Mem0) ---- */

typedef struct {
    int added;
    int updated;
    int deleted;
    int noop;
} pipe_counts_t;

static void pipe_find_neighbors(const claw_memory_fact_t *fact,
                                const float *fact_vec,
                                const claw_memory_item_list_t *items,
                                char neighbors[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX],
                                int neighbor_index[CLAW_MEMORY_RECONCILE_TOPK])
{
    char tokens[CLAW_MEMORY_QUERY_MAX_TOKENS][CLAW_MEMORY_TOKEN_MAX];
    char query[512];
    float best[CLAW_MEMORY_RECONCILE_TOPK] = {0};
    size_t token_count;
    size_t i;
    size_t k;

    snprintf(query, sizeof(query), "%s %s %s", fact->keywords, fact->tags, fact->content);
    token_count = claw_memory_tokenize(query, tokens, CLAW_MEMORY_QUERY_MAX_TOKENS);
    for (k = 0; k < CLAW_MEMORY_RECONCILE_TOPK; k++) {
        neighbors[k][0] = '\0';
        neighbor_index[k] = -1;
    }
    for (i = 0; i < items->count; i++) {
        const claw_memory_item_t *item = &items->items[i];
        const int8_t *vec = fact_vec ? claw_memory_vectors_get(item->id) : NULL;
        float score;

        if (item->deleted) {
            continue;
        }
        if (vec) {
            score = claw_memory_vec_cosine(vec, fact_vec);
            if (score < PIPE_NEIGHBOR_MIN_COS) {
                continue;
            }
        } else {
            score = claw_memory_keyword_match(tokens, token_count, item->content, item->tags, item->keywords);
            if (score < PIPE_NEIGHBOR_MIN_KW) {
                continue;
            }
        }
        for (k = 0; k < CLAW_MEMORY_RECONCILE_TOPK; k++) {
            if (neighbor_index[k] < 0 || score > best[k]) {
                memmove(&best[k + 1], &best[k], (CLAW_MEMORY_RECONCILE_TOPK - k - 1) * sizeof(best[0]));
                memmove(&neighbor_index[k + 1], &neighbor_index[k],
                        (CLAW_MEMORY_RECONCILE_TOPK - k - 1) * sizeof(neighbor_index[0]));
                memmove(neighbors[k + 1], neighbors[k], (CLAW_MEMORY_RECONCILE_TOPK - k - 1) * CLAW_MEMORY_ID_MAX);
                best[k] = score;
                neighbor_index[k] = (int)i;
                safe_copy(neighbors[k], CLAW_MEMORY_ID_MAX, item->id);
                break;
            }
        }
    }
}

static void pipe_reconcile_and_store(const claw_memory_fact_t *facts, size_t count, pipe_counts_t *counts)
{
    char (*neighbors)[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX] = NULL;
    claw_memory_decision_t *decisions = NULL;
    claw_memory_item_list_t items = {0};
    claw_memory_item_t *item = NULL;
    pipe_text_t prompt = {0};
    float *vecs = NULL;
    bool has_vecs = false;
    bool any_neighbor = false;
    size_t i;

    neighbors = calloc(count, sizeof(*neighbors));
    decisions = calloc(count, sizeof(*decisions));
    item = calloc(1, sizeof(*item));
    if (!neighbors || !decisions || !item) {
        goto cleanup;
    }
    if (claw_memory_embed_enabled()) {
        const char *texts[CLAW_MEMORY_FACTS_MAX];

        vecs = heap_caps_malloc(count * CLAW_MEMORY_EMBED_DIM * sizeof(float), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        for (i = 0; i < count; i++) {
            texts[i] = facts[i].content;
        }
        has_vecs = vecs && claw_memory_embed_texts(texts, count, vecs) == ESP_OK;
    }

    claw_memory_lock();
    if (claw_memory_load_current_items(&items) == ESP_OK) {
        pipe_text_appendf(&prompt, "Candidates and the most similar existing memories:\n");
        for (i = 0; i < count; i++) {
            int index[CLAW_MEMORY_RECONCILE_TOPK];
            size_t k;

            pipe_find_neighbors(&facts[i], has_vecs ? vecs + i * CLAW_MEMORY_EMBED_DIM : NULL,
                                &items, neighbors[i], index);
            pipe_text_appendf(&prompt, "[%u] %s (tags: %s)\n", (unsigned)i, facts[i].content, facts[i].tags);
            for (k = 0; k < CLAW_MEMORY_RECONCILE_TOPK && index[k] >= 0; k++) {
                char date[16];

                pipe_format_date(items.items[index[k]].updated_at, date, sizeof(date));
                pipe_text_appendf(&prompt, "    existing %s (updated %s): %s\n",
                                  neighbors[i][k], date, items.items[index[k]].content);
                any_neighbor = true;
            }
        }
    }
    claw_memory_unlock();

    if (any_neighbor && prompt.buf) {
        cJSON *root = NULL;

        if (pipe_llm_json(k_reconcile_prompt, prompt.buf, &root) != ESP_OK) {
            /* Without a decision nothing is stored; the watermark stays and the
             * transcript is retried later. */
            counts->noop = -1;
            goto cleanup;
        }
        claw_memory_parse_decisions(root, count,
                                    (const char (*)[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX])neighbors,
                                    facts, decisions);
        cJSON_Delete(root);
    } else {
        claw_memory_parse_decisions(NULL, count, NULL, facts, decisions);
    }

    for (i = 0; i < count; i++) {
        bool changed = false;

        memset(item, 0, sizeof(*item));
        safe_copy(item->content, sizeof(item->content),
                  decisions[i].op == CLAW_MEMORY_OP_UPDATE ? decisions[i].content : facts[i].content);
        safe_copy(item->tags, sizeof(item->tags), facts[i].tags);
        safe_copy(item->keywords, sizeof(item->keywords), facts[i].keywords);
        safe_copy(item->source, sizeof(item->source), "auto_session");
        item->importance = facts[i].importance;
        item->kind = facts[i].kind;

        switch (decisions[i].op) {
        case CLAW_MEMORY_OP_ADD:
            if (claw_memory_store_with_result(item, &changed) == ESP_OK && changed) {
                counts->added++;
                if (has_vecs) {
                    claw_memory_lock();
                    (void)claw_memory_vectors_put(item->id, vecs + i * CLAW_MEMORY_EMBED_DIM);
                    claw_memory_unlock();
                }
            } else {
                counts->noop++;
            }
            break;
        case CLAW_MEMORY_OP_UPDATE:
            safe_copy(item->id, sizeof(item->id), decisions[i].id);
            if (claw_memory_update_with_result(item, &changed) == ESP_OK && changed) {
                counts->updated++;
            } else {
                counts->noop++;
            }
            break;
        case CLAW_MEMORY_OP_DELETE:
            if (claw_memory_forget(decisions[i].id) == ESP_OK) {
                counts->deleted++;
            } else {
                counts->noop++;
            }
            break;
        default:
            counts->noop++;
            break;
        }
    }

cleanup:
    claw_memory_item_list_free(&items);
    heap_caps_free(vecs);
    free(prompt.buf);
    free(neighbors);
    free(decisions);
    free(item);
}

/* ---- stage 1: session extraction ---- */

static esp_err_t pipe_extract_session(const char *path)
{
    claw_memory_fact_t *facts = NULL;
    pipe_counts_t counts = {0};
    cJSON *index_root = NULL;
    cJSON *root = NULL;
    char *transcript = NULL;
    char *user_text = NULL;
    char summary[PIPE_SUMMARY_MAX_CHARS * 4 + 1] = {0};
    uint32_t from = 0;
    uint32_t turns = 0;
    size_t fact_count = 0;
    size_t dropped = 0;
    esp_err_t err;

    claw_memory_lock();
    err = claw_memory_load_index(&index_root);
    if (err == ESP_OK) {
        from = pipe_state_number(pipe_watermark(claw_memory_pipeline_state(index_root), path), "n");
        err = claw_memory_session_read_transcript(path, from, PIPE_TRANSCRIPT_MAX, &transcript, &turns);
        if (err == ESP_OK && turns < from) {
            /* The log was recreated: start over. */
            free(transcript);
            transcript = NULL;
            from = 0;
            err = claw_memory_session_read_transcript(path, 0, PIPE_TRANSCRIPT_MAX, &transcript, &turns);
        }
    }
    cJSON_Delete(index_root);
    index_root = NULL;
    claw_memory_unlock();
    if (err != ESP_OK || turns == from) {
        free(transcript);
        return err == ESP_ERR_NOT_FOUND ? ESP_OK : err;
    }

    if (s_pipe.runtime) {
        user_text = dup_printf("Transcript:\n%s", transcript);
        err = user_text ? pipe_llm_json(k_extract_prompt, user_text, &root) : ESP_ERR_NO_MEM;
        free(user_text);
    } else {
        err = ESP_ERR_INVALID_STATE;
    }
    free(transcript);
    if (err != ESP_OK) {
        return err;
    }

    facts = calloc(CLAW_MEMORY_FACTS_MAX, sizeof(*facts));
    if (!facts) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    fact_count = claw_memory_parse_facts(root, facts, CLAW_MEMORY_FACTS_MAX, &dropped);
    {
        const char *text = cJSON_GetStringValue(cJSON_GetObjectItem(root, "session_summary"));

        if (text && !claw_memory_text_has_secret(text)) {
            utf8_copy_chars(summary, sizeof(summary), text, PIPE_SUMMARY_MAX_CHARS);
        }
    }
    cJSON_Delete(root);

    if (fact_count > 0) {
        pipe_reconcile_and_store(facts, fact_count, &counts);
    }
    free(facts);
    if (counts.noop < 0) {
        return ESP_FAIL;
    }

    claw_memory_lock();
    err = claw_memory_load_index(&index_root);
    if (err == ESP_OK) {
        cJSON *state = claw_memory_pipeline_state(index_root);

        pipe_set_watermark(state, path, turns);
        pipe_add_summary(state, path, summary);
        pipe_state_set_number(state, "facts_pending",
                              pipe_state_number(state, "facts_pending") + (uint32_t)(counts.added + counts.updated));
        err = claw_memory_save_index(index_root);
    }
    cJSON_Delete(index_root);
    claw_memory_unlock();

    ESP_LOGI(TAG, "session extract turns=%" PRIu32 "->%" PRIu32 " facts=%u added=%d updated=%d deleted=%d noop=%d dropped=%u",
             from, turns, (unsigned)fact_count, counts.added, counts.updated, counts.deleted, counts.noop,
             (unsigned)dropped);
    if (counts.added + counts.updated > 0) {
        pipe_backfill_vectors();
    }
    return err;
}

/* Keeps the newest part of a large log and replaces the rest with the stored
 * session summaries. Only already extracted turns may be dropped. */
static esp_err_t pipe_compact_session(const char *path, bool needs_extraction, size_t *out_freed)
{
    cJSON *index_root = NULL;
    cJSON *it;
    pipe_text_t summary = {0};
    uint32_t from = UINT32_MAX;
    uint32_t dropped = 0;
    size_t before = file_size_bytes(path);
    esp_err_t err;

    claw_memory_lock();
    err = claw_memory_load_index(&index_root);
    if (err == ESP_OK) {
        cJSON *state = claw_memory_pipeline_state(index_root);

        if (needs_extraction) {
            from = pipe_state_number(pipe_watermark(state, path), "n");
        }
        cJSON_ArrayForEach(it, pipe_state_child(state, "summaries", true)) {
            const char *f = cJSON_GetStringValue(cJSON_GetObjectItem(it, "f"));
            const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(it, "s"));

            if (f && s && strcmp(f, pipe_basename(path)) == 0) {
                pipe_text_appendf(&summary, "- %s\n", s);
            }
        }
        err = claw_memory_session_compact_with_summary(path, CLAW_MEMORY_GC_KEEP_BYTES,
                                                       summary.buf, from, &dropped);
        if (err == ESP_OK && dropped > 0 && needs_extraction) {
            /* Dropped turns were extracted; the two summary records count as extracted too. */
            pipe_set_watermark(state, path, from - dropped + 2);
            err = claw_memory_save_index(index_root);
        }
    }
    cJSON_Delete(index_root);
    claw_memory_unlock();
    free(summary.buf);
    if (out_freed) {
        size_t after = file_size_bytes(path);

        *out_freed = before > after ? before - after : 0;
    }
    return err;
}

/* ---- stage 2: consolidation ---- */

typedef struct {
    float score;
    size_t index;
} pipe_ranked_t;

static int pipe_ranked_desc(const void *a, const void *b)
{
    float sa = ((const pipe_ranked_t *)a)->score;
    float sb = ((const pipe_ranked_t *)b)->score;

    return sa < sb ? 1 : (sa > sb ? -1 : 0);
}

static size_t pipe_cap_markdown(char *text, size_t max_bytes)
{
    char *line = text;
    char *out = text;
    size_t len;

    /* Drop lines that carry secrets, then cut at the last full line. */
    while (line && *line) {
        char *next = strchr(line, '\n');
        size_t line_len = next ? (size_t)(next - line) + 1 : strlen(line);
        char saved = line[line_len];

        line[line_len] = '\0';
        if (!claw_memory_text_has_secret(line)) {
            memmove(out, line, line_len + 1);
            out += line_len;
        }
        line[line_len] = saved;
        line = next ? line + line_len : NULL;
    }
    *out = '\0';
    len = strlen(text);
    if (len > max_bytes) {
        char *cut = text + max_bytes;

        *cut = '\0';
        cut = strrchr(text, '\n');
        if (cut) {
            cut[1] = '\0';
        }
        len = strlen(text);
    }
    return len;
}

static esp_err_t pipe_consolidate(const char *reason)
{
    claw_memory_item_list_t items = {0};
    pipe_ranked_t *ranked = NULL;
    pipe_text_t prompt = {0};
    cJSON *index_root = NULL;
    cJSON *root = NULL;
    cJSON *it;
    char *user_md_old = NULL;
    char *user_md = NULL;
    char *memory_md = NULL;
    uint32_t now = claw_memory_now_sec();
    size_t ranked_count = 0;
    size_t records = 0;
    size_t summaries = 0;
    size_t user_len = 0;
    size_t memory_len = 0;
    size_t i;
    esp_err_t err;

    claw_memory_lock();
    pipe_flush_access();
    claw_memory_compact_internal(true);
    err = claw_memory_load_current_items(&items);
    if (err == ESP_OK) {
        err = claw_memory_load_index(&index_root);
    }
    if (err == ESP_OK) {
        ranked = calloc(items.count ? items.count : 1, sizeof(*ranked));
        err = ranked ? ESP_OK : ESP_ERR_NO_MEM;
    }
    if (err == ESP_OK) {
        for (i = 0; i < items.count; i++) {
            if (!items.items[i].deleted) {
                ranked[ranked_count].score = claw_memory_rank_score(1.0f, now, items.items[i].updated_at,
                                                                    items.items[i].access_count,
                                                                    items.items[i].importance);
                ranked[ranked_count++].index = i;
            }
        }
        qsort(ranked, ranked_count, sizeof(*ranked), pipe_ranked_desc);
        if (read_file_dup(s_memory.user_path, &user_md_old) == ESP_OK && strlen(user_md_old) > 3072) {
            user_md_old[3072] = '\0';
        }
        pipe_text_appendf(&prompt, "Current user.md:\n%s\n\nStored memories (most relevant first):\n",
                          user_md_old ? user_md_old : "(empty)");
        for (i = 0; i < ranked_count && prompt.len < PIPE_RECORDS_TEXT_MAX; i++) {
            const claw_memory_item_t *item = &items.items[ranked[i].index];
            char date[16];

            pipe_format_date(item->updated_at, date, sizeof(date));
            pipe_text_appendf(&prompt, "- [%s, importance %u, %s] %s\n", claw_memory_kind_name(item->kind),
                              item->importance ? item->importance : 3, date, item->content);
            records++;
        }
        pipe_text_appendf(&prompt, "\nSession summaries (oldest first):\n");
        cJSON_ArrayForEach(it, pipe_state_child(claw_memory_pipeline_state(index_root), "summaries", true)) {
            char date[16];

            pipe_format_date(pipe_state_number(it, "t"), date, sizeof(date));
            pipe_text_appendf(&prompt, "- %s: %s\n", date, cJSON_GetStringValue(cJSON_GetObjectItem(it, "s")));
            summaries++;
        }
    }
    cJSON_Delete(index_root);
    index_root = NULL;
    claw_memory_unlock();
    claw_memory_item_list_free(&items);
    free(ranked);
    free(user_md_old);
    if (err != ESP_OK || !prompt.buf) {
        free(prompt.buf);
        return err != ESP_OK ? err : ESP_ERR_NO_MEM;
    }

    if (records == 0 && summaries == 0) {
        /* Nothing to consolidate yet: keep the files, just mark the day as done. */
        free(prompt.buf);
        root = cJSON_CreateObject();
    } else {
        err = pipe_llm_json(k_consolidate_prompt, prompt.buf, &root);
        free(prompt.buf);
        if (err != ESP_OK) {
            return err;
        }
    }
    user_md = dup_printf("%s\n", cJSON_GetStringValue(cJSON_GetObjectItem(root, "user_md")) ?: "");
    memory_md = dup_printf("%s\n", cJSON_GetStringValue(cJSON_GetObjectItem(root, "memory_md")) ?: "");
    cJSON_Delete(root);
    if (!user_md || !memory_md) {
        free(user_md);
        free(memory_md);
        return ESP_ERR_NO_MEM;
    }
    user_len = pipe_cap_markdown(user_md, CLAW_MEMORY_USER_MD_MAX);
    memory_len = pipe_cap_markdown(memory_md, CLAW_MEMORY_MARKDOWN_MAX);

    claw_memory_lock();
    if (user_len > 8) {
        err = write_file_atomic(s_memory.user_path, user_md);
    }
    if (err == ESP_OK && memory_len > 8) {
        err = write_file_atomic(s_memory.markdown_path, memory_md);
    }
    if (err == ESP_OK && claw_memory_load_index(&index_root) == ESP_OK) {
        cJSON *state = claw_memory_pipeline_state(index_root);
        char day[16];

        pipe_format_date(now, day, sizeof(day));
        pipe_state_set_number(state, "consolidated_at", now);
        pipe_state_set_number(state, "facts_pending", 0);
        cJSON_DeleteItemFromObject(state, "consolidated_day");
        cJSON_AddStringToObject(state, "consolidated_day", day);
        err = claw_memory_save_index(index_root);
        cJSON_Delete(index_root);
    }
    claw_memory_unlock();
    free(user_md);
    free(memory_md);

    ESP_LOGI(TAG, "consolidation reason=%s records=%u user_md=%uB memory_md=%uB err=%s",
             reason, (unsigned)records, (unsigned)user_len, (unsigned)memory_len, esp_err_to_name(err));
    return err;
}

static const char *pipe_consolidation_due(void)
{
    cJSON *index_root = NULL;
    const char *reason = NULL;
    uint32_t now = claw_memory_now_sec();

    if (s_pipe.consolidate_requested) {
        return "request";
    }
    claw_memory_lock();
    if (claw_memory_load_index(&index_root) == ESP_OK) {
        cJSON *state = claw_memory_pipeline_state(index_root);
        const char *last_day = cJSON_GetStringValue(cJSON_GetObjectItem(state, "consolidated_day"));
        time_t raw = (time_t)now;
        struct tm tm_info;
        char day[16];

        pipe_format_date(now, day, sizeof(day));
        if (pipe_state_number(state, "facts_pending") >= PIPE_CONSOLIDATE_FACTS) {
            reason = "facts";
        } else if (pipe_clock_valid(now) && localtime_r(&raw, &tm_info) &&
                   tm_info.tm_hour * 60 + tm_info.tm_min >= PIPE_CONSOLIDATE_MINUTE &&
                   (!last_day || strcmp(last_day, day) != 0)) {
            reason = "nightly";
        }
    }
    cJSON_Delete(index_root);
    claw_memory_unlock();
    return reason;
}

/* ---- storage GC ---- */

typedef struct {
    char *session_id;
    char *parent_id;
    char *path;
    bool current;
} pipe_known_session_t;

typedef struct {
    pipe_known_session_t *items;
    size_t count;
    size_t cap;
} pipe_known_list_t;

typedef struct {
    char path[CLAW_MEMORY_MAX_PATH];
    const pipe_known_session_t *known;
    bool is_chat;
    bool behind;
    claw_memory_gc_entry_t gc;
} pipe_gc_session_t;

static void pipe_known_visit(const char *session_id, const char *parent_session_id, bool current, void *user_ctx)
{
    pipe_known_list_t *list = (pipe_known_list_t *)user_ctx;
    pipe_known_session_t *entry;

    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 16;
        pipe_known_session_t *grown = realloc(list->items, cap * sizeof(*grown));

        if (!grown) {
            return;
        }
        list->items = grown;
        list->cap = cap;
    }
    entry = &list->items[list->count];
    entry->session_id = strdup(session_id);
    entry->parent_id = parent_session_id ? strdup(parent_session_id) : NULL;
    entry->path = claw_memory_session_path_dup(session_id);
    entry->current = current;
    if (entry->session_id && entry->path) {
        list->count++;
    } else {
        free(entry->session_id);
        free(entry->parent_id);
        free(entry->path);
    }
}

static void pipe_known_free(pipe_known_list_t *list)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        free(list->items[i].session_id);
        free(list->items[i].parent_id);
        free(list->items[i].path);
    }
    free(list->items);
}

static size_t pipe_dir_bytes(const char *dir_path, bool recurse_once)
{
    char path[CLAW_MEMORY_MAX_PATH + 64];
    struct dirent *entry;
    struct stat st;
    size_t total = 0;
    DIR *dir = opendir(dir_path);

    while (dir && (entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' ||
            snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(path) ||
            stat(path, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            total += recurse_once ? pipe_dir_bytes(path, false) : 0;
        } else {
            total += (size_t)st.st_size;
        }
    }
    if (dir) {
        closedir(dir);
    }
    return total;
}

static size_t pipe_skills_state_path(const char *log_path, char *out, size_t size)
{
    size_t len = strlen(log_path);

    if (len < 4 || len - 4 + sizeof(".skills.json") > size) {
        return 0;
    }
    memcpy(out, log_path, len - 4);
    strcpy(out + len - 4, ".skills.json");
    return file_size_bytes(out);
}

static size_t pipe_gc_scan(pipe_gc_session_t *sessions, size_t max, const pipe_known_list_t *known, uint32_t now)
{
    char idx_path[CLAW_MEMORY_MAX_PATH + 8];
    char skills_path[CLAW_MEMORY_MAX_PATH + 16];
    struct dirent *entry;
    struct stat st;
    size_t count = 0;
    DIR *dir = opendir(s_memory.session_root_dir);

    while (dir && count < max && (entry = readdir(dir)) != NULL) {
        pipe_gc_session_t *s = &sessions[count];
        size_t len = strlen(entry->d_name);
        size_t i;

        if (len < 5 || strcmp(entry->d_name + len - 4, ".log") != 0 ||
            snprintf(s->path, sizeof(s->path), "%s/%s", s_memory.session_root_dir, entry->d_name) >= (int)sizeof(s->path) ||
            stat(s->path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        s->known = NULL;
        for (i = 0; i < known->count; i++) {
            if (strcmp(known->items[i].path, s->path) == 0) {
                s->known = &known->items[i];
                break;
            }
        }
        snprintf(idx_path, sizeof(idx_path), "%s.idx", s->path);
        s->gc.log_bytes = (uint32_t)st.st_size;
        s->gc.bytes = (uint32_t)(st.st_size + file_size_bytes(idx_path) +
                                 pipe_skills_state_path(s->path, skills_path, sizeof(skills_path)));
        s->gc.mtime = (uint32_t)st.st_mtime;
        /* Recently written logs may belong to a running subagent or trigger. */
        s->gc.active = (s->known && s->known->current) ||
                       (pipe_clock_valid(now) && s->gc.mtime <= now && now - s->gc.mtime < PIPE_GC_RECENT_SEC);
        s->is_chat = s->known ? (!s->known->parent_id && pipe_is_chat_session(s->known->session_id)) :
                     pipe_is_chat_file(entry->d_name);
        count++;
    }
    if (dir) {
        closedir(dir);
    }
    return count;
}

/* Lock held. A chat log counts as extracted once the watermark covers all
 * turns and a consolidation ran afterwards (its summary is in MEMORY.md). */
static void pipe_gc_mark_extracted(pipe_gc_session_t *sessions, size_t count)
{
    cJSON *index_root = NULL;
    cJSON *state;
    uint32_t consolidated_at;
    size_t i;

    if (claw_memory_load_index(&index_root) != ESP_OK) {
        return;
    }
    state = claw_memory_pipeline_state(index_root);
    consolidated_at = pipe_state_number(state, "consolidated_at");
    for (i = 0; i < count; i++) {
        cJSON *mark = pipe_watermark(state, sessions[i].path);
        uint32_t turns = 0;

        sessions[i].gc.extracted = !sessions[i].is_chat;
        sessions[i].behind = false;
        if (!sessions[i].is_chat) {
            continue;
        }
        if (claw_memory_session_turn_count(sessions[i].path, &turns) != ESP_OK) {
            /* Unreadable log: nothing left to extract from it. */
            sessions[i].gc.extracted = true;
            continue;
        }
        sessions[i].behind = pipe_state_number(mark, "n") < turns;
        sessions[i].gc.extracted = !sessions[i].behind &&
                                   (turns == 0 || pipe_state_number(mark, "t") <= consolidated_at);
    }
    cJSON_Delete(index_root);
}

static void pipe_gc_prune_watermarks(void)
{
    cJSON *index_root = NULL;
    char path[CLAW_MEMORY_MAX_PATH + 64];
    bool changed = false;

    claw_memory_lock();
    if (claw_memory_load_index(&index_root) == ESP_OK) {
        cJSON *marks = pipe_state_child(claw_memory_pipeline_state(index_root), "watermarks", false);
        cJSON *it = marks ? marks->child : NULL;

        while (it) {
            cJSON *next = it->next;

            snprintf(path, sizeof(path), "%s/%s", s_memory.session_root_dir, it->string);
            if (!file_size_bytes(path) && access(path, F_OK) != 0) {
                cJSON_Delete(cJSON_DetachItemViaPointer(marks, it));
                changed = true;
            }
            it = next;
        }
        if (changed) {
            claw_memory_save_index(index_root);
        }
    }
    cJSON_Delete(index_root);
    claw_memory_unlock();
}

static void pipe_dav_sweep(const char *dir_path, int depth, uint32_t now, int *removed, int *restored)
{
    char path[CLAW_MEMORY_MAX_PATH + 64];
    char original[CLAW_MEMORY_MAX_PATH + 64];
    struct dirent *entry;
    struct stat st;
    DIR *dir;

    if (depth > 6 || !(dir = opendir(dir_path))) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        size_t len = strlen(entry->d_name);
        bool is_tmp = len > 7 && strcmp(entry->d_name + len - 7, ".davtmp") == 0;
        bool is_bak = len > 7 && strcmp(entry->d_name + len - 7, ".davbak") == 0;
        bool old;

        if (entry->d_name[0] == '.' ||
            snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(path) ||
            stat(path, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            pipe_dav_sweep(path, depth + 1, now, removed, restored);
            continue;
        }
        if (!is_tmp && !is_bak) {
            continue;
        }
        /* Age check keeps running uploads safe; a pre-NTP mtime counts as old
         * once the device has been up longer than the age limit. */
        old = (uint32_t)st.st_mtime < CLAW_MEMORY_MIN_VALID_EPOCH ?
              pipe_uptime_sec() > PIPE_DAV_TMP_AGE_SEC :
              ((uint32_t)st.st_mtime <= now && now - (uint32_t)st.st_mtime > PIPE_DAV_TMP_AGE_SEC);
        if (!old) {
            continue;
        }
        snprintf(original, sizeof(original), "%.*s", (int)(strlen(path) - 7), path);
        if (is_bak && access(original, F_OK) != 0) {
            if (rename(path, original) == 0) {
                (*restored)++;
            }
        } else if (unlink(path) == 0) {
            (*removed)++;
        }
    }
    closedir(dir);
}

static void pipe_storage_gc(void)
{
    pipe_known_list_t known = {0};
    pipe_gc_session_t *sessions = NULL;
    uint8_t actions[PIPE_GC_SESSIONS_MAX];
    uint32_t now = claw_memory_now_sec();
    uint32_t session_bytes = 0;
    uint32_t total;
    size_t fixed;
    size_t freed = 0;
    size_t count;
    size_t i;
    int extracted = 0;
    int deleted = 0;
    int compacted = 0;
    int dav_removed = 0;
    int dav_restored = 0;
    bool maps_ok;

    if (s_memory.storage_root_dir[0] && pipe_clock_valid(now)) {
        pipe_dav_sweep(s_memory.storage_root_dir, 0, now, &dav_removed, &dav_restored);
    }

    sessions = heap_caps_calloc(PIPE_GC_SESSIONS_MAX, sizeof(*sessions), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!sessions) {
        return;
    }
    maps_ok = claw_session_mgr_visit_sessions(pipe_known_visit, &known) == ESP_OK;
    claw_memory_lock();
    count = pipe_gc_scan(sessions, PIPE_GC_SESSIONS_MAX, &known, now);
    pipe_gc_mark_extracted(sessions, count);
    claw_memory_unlock();
    for (i = 0; !maps_ok && i < count; i++) {
        /* Without the chat maps the current sessions are unknown: compact only. */
        sessions[i].gc.active = true;
    }

    /* Old inactive chat logs that were never extracted get extracted now and
     * become eligible after the next consolidation. */
    for (i = 0; i < count && extracted < PIPE_GC_EXTRACT_PER_RUN && s_pipe.runtime; i++) {
        if (sessions[i].behind && !sessions[i].gc.active &&
            pipe_extract_session(sessions[i].path) == ESP_OK) {
            extracted++;
        }
    }

    for (i = 0; i < count; i++) {
        session_bytes += sessions[i].gc.bytes;
    }
    fixed = pipe_dir_bytes(s_memory.session_root_dir, true);
    fixed = fixed > session_bytes ? fixed - session_bytes : 0;
    {
        claw_memory_gc_entry_t *entries = calloc(count ? count : 1, sizeof(*entries));

        if (!entries) {
            goto cleanup;
        }
        for (i = 0; i < count; i++) {
            entries[i] = sessions[i].gc;
        }
        total = claw_memory_gc_plan(entries, count, now, (uint32_t)fixed, actions);
        free(entries);
    }

    for (i = 0; i < count; i++) {
        pipe_gc_session_t *s = &sessions[i];
        size_t bytes = 0;

        if (actions[i] == CLAW_MEMORY_GC_DELETE) {
            esp_err_t err;

            if (s->known) {
                /* Through the session manager so chat_map/subagent_map stay consistent.
                 * Its delete handler takes the memory lock itself. */
                err = claw_session_mgr_delete_session(s->known->session_id, s->known->parent_id);
                bytes = err == ESP_OK ? s->gc.bytes : 0;
            } else {
                char skills_path[CLAW_MEMORY_MAX_PATH + 16];
                size_t skills = pipe_skills_state_path(s->path, skills_path, sizeof(skills_path));

                claw_memory_lock();
                err = claw_memory_session_delete_files(s->path, NULL, &bytes);
                claw_memory_unlock();
                if (err == ESP_OK && skills && unlink(skills_path) == 0) {
                    bytes += skills;
                }
            }
            if (err == ESP_OK) {
                deleted++;
                freed += bytes;
            } else {
                ESP_LOGW(TAG, "session gc delete failed: %s", esp_err_to_name(err));
            }
        } else if (actions[i] == CLAW_MEMORY_GC_COMPACT) {
            if (s->is_chat && s->behind && pipe_extract_session(s->path) != ESP_OK) {
                continue;
            }
            if (pipe_compact_session(s->path, s->is_chat, &bytes) == ESP_OK && bytes > 0) {
                compacted++;
                freed += bytes;
            }
        }
    }
    pipe_gc_prune_watermarks();
    ESP_LOGI(TAG, "session gc sessions=%u extracted=%d deleted=%d compacted=%d freed=%uB projected=%" PRIu32
             "B dav_removed=%d dav_restored=%d",
             (unsigned)count, extracted, deleted, compacted, (unsigned)freed, total, dav_removed, dav_restored);

cleanup:
    heap_caps_free(sessions);
    pipe_known_free(&known);
}

/* ---- worker ---- */

static bool pipe_take_due_session(char *path, size_t path_size)
{
    uint32_t up = pipe_uptime_sec();
    bool found = false;
    size_t i;

    claw_memory_lock();
    for (i = 0; i < PIPE_TRACKED_MAX && !found; i++) {
        pipe_tracked_t *t = &s_pipe.tracked[i];

        if (t->pending &&
            (t->force || (up - t->last_activity >= PIPE_IDLE_SEC &&
                          (!t->last_attempt || up - t->last_attempt >= PIPE_RETRY_SEC)))) {
            safe_copy(path, path_size, t->path);
            t->pending = false;
            t->force = false;
            t->last_attempt = up;
            found = true;
        }
    }
    claw_memory_unlock();
    return found;
}

static void pipe_retry_later(const char *path)
{
    claw_memory_lock();
    pipe_track(path)->pending = true;
    claw_memory_unlock();
}

static void pipe_tick(void)
{
    char path[CLAW_MEMORY_MAX_PATH];
    const char *reason;
    int rounds;

    for (rounds = 0; rounds < 2 && pipe_take_due_session(path, sizeof(path)); rounds++) {
        if (pipe_extract_session(path) != ESP_OK) {
            pipe_retry_later(path);
        } else if (file_size_bytes(path) > CLAW_MEMORY_GC_COMPACT_BYTES) {
            (void)pipe_compact_session(path, true, NULL);
        }
    }

    claw_memory_lock();
    if (s_pipe.access_count && pipe_uptime_sec() - s_pipe.last_access_flush >= PIPE_ACCESS_FLUSH_SEC) {
        pipe_flush_access();
    }
    claw_memory_unlock();

    reason = s_pipe.runtime ? pipe_consolidation_due() : NULL;
    if (reason) {
        s_pipe.consolidate_requested = false;
        if (pipe_consolidate(reason) == ESP_OK) {
            pipe_backfill_vectors();
            pipe_storage_gc();
        }
    }

    if (!s_pipe.boot_done && pipe_uptime_sec() >= PIPE_BOOT_DELAY_SEC) {
        s_pipe.boot_done = true;
        pipe_storage_gc();
    }
}

static void pipe_task(void *arg)
{
    (void)arg;
    for (;;) {
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(PIPE_TICK_MS));
        pipe_tick();
    }
}

esp_err_t claw_memory_pipeline_init(const claw_memory_config_t *config)
{
    const claw_memory_llm_config_t *llm = &config->llm;
    char *error_message = NULL;
    esp_err_t err;

    if (s_pipe.task || !config->enable_background_pipeline) {
        return ESP_OK;
    }
    if (llm->api_key && llm->api_key[0] && llm->model && llm->model[0] &&
        llm->backend_type && llm->backend_type[0]) {
        err = claw_llm_runtime_init(&s_pipe.runtime,
                                    &(claw_llm_runtime_config_t) {
                                        .api_key = llm->api_key,
                                        .backend_type = llm->backend_type,
                                        .model = llm->model,
                                        .base_url = llm->base_url,
                                        .auth_type = llm->auth_type,
                                        .max_tokens_field = llm->max_tokens_field,
                                        .timeout_ms = llm->timeout_ms,
                                        .max_tokens = llm->max_tokens,
                                        .image_max_bytes = llm->image_max_bytes,
                                        .supports_tools = llm->supports_tools,
                                        .supports_vision = llm->supports_vision,
                                        .image_remote_url_only = llm->image_remote_url_only,
                                    },
                                    &error_message);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to init memory LLM runtime: %s",
                     error_message ? error_message : esp_err_to_name(err));
            s_pipe.runtime = NULL;
        }
        free(error_message);
    } else {
        ESP_LOGI(TAG, "Memory extraction disabled: LLM config incomplete");
    }

    if (claw_task_create(&(claw_task_config_t) {
                             .name = "claw_mem_pipe",
                             .stack_size = PIPE_STACK_SIZE,
                             .priority = PIPE_PRIORITY,
                             .core_id = tskNO_AFFINITY,
                             .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                         },
                         pipe_task,
                         NULL,
                         &s_pipe.task) != pdPASS) {
        if (s_pipe.runtime) {
            claw_llm_runtime_deinit(s_pipe.runtime);
            s_pipe.runtime = NULL;
        }
        s_pipe.task = NULL;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Memory pipeline worker ready (llm=%s, embeddings=%s)",
             s_pipe.runtime ? "on" : "off", claw_memory_embed_enabled() ? "on" : "off");
    return ESP_OK;
}
