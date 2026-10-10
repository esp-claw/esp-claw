/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Host tests for the session history (claw_memory_session.c, compiled unchanged against stubs):
 * whatever is persisted, compacted or trimmed, the loaded history never contains an assistant
 * tool call without all of its outputs, or an output without its call.
 */
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "claw_memory_internal.h"

static int s_failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            s_failures++; \
        } \
    } while (0)

/* ---- stubs for what claw_memory_session.c links against ---- */

claw_memory_state_t s_memory;
static int s_fail_write_countdown = -1; /* fail the Nth raw record write (0 = next) */

const char *esp_err_to_name(esp_err_t err)
{
    static char buf[16];

    snprintf(buf, sizeof(buf), "err %d", err);
    return buf;
}

char *dup_printf(const char *fmt, ...)
{
    va_list args;
    char *out = NULL;

    va_start(args, fmt);
    if (vasprintf(&out, fmt, args) < 0) {
        out = NULL;
    }
    va_end(args);
    return out;
}

size_t file_size_bytes(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 ? (size_t)st.st_size : 0;
}

esp_err_t ensure_parent_dir(const char *path)
{
    (void)path;
    return ESP_OK;
}

char *claw_memory_session_path_dup(const char *session_id)
{
    return dup_printf("%s/s_%s.log", s_memory.session_root_dir, session_id);
}

size_t claw_memory_text_buffer_size(size_t max_chars)
{
    return max_chars * 4 + 1;
}

void claw_memory_normalize_session_text(const char *src, char *dst, size_t dst_size, size_t max_chars)
{
    (void)max_chars;
    snprintf(dst, dst_size, "%s", src ? src : "");
}

/* Same as the real writer, plus fault injection: the failing write stops half way (disk full). */
esp_err_t claw_memory_write_session_raw_record(FILE *file, const char *json_text,
                                               uint32_t *out_offset, uint32_t *out_length)
{
    size_t len = strlen(json_text);
    long offset = ftell(file);

    if (s_fail_write_countdown >= 0 && s_fail_write_countdown-- == 0) {
        fwrite(json_text, 1, len / 2, file);
        return ESP_FAIL;
    }
    if (offset < 0 || fwrite(json_text, 1, len, file) != len || fputc('\n', file) == EOF) {
        return ESP_FAIL;
    }
    *out_offset = (uint32_t)offset;
    *out_length = (uint32_t)(len + 1);
    return ESP_OK;
}

esp_err_t line_list_merge_unique(char **dst, const char *src)
{
    (void)dst;
    (void)src;
    return ESP_OK;
}

char *claw_memory_format_update_stage_note(const char *summary_list)
{
    (void)summary_list;
    return NULL;
}

size_t claw_memory_tail_offset(const char *text, size_t len, size_t max_bytes)
{
    (void)text;
    return len > max_bytes ? len - max_bytes : 0;
}

void claw_memory_lock(void) {}
void claw_memory_unlock(void) {}
void claw_memory_pipeline_note_persist(const char *session_id, const char *data_path)
{
    (void)session_id;
    (void)data_path;
}
void claw_memory_pipeline_note_request(const char *session_id)
{
    (void)session_id;
}

esp_err_t claw_core_publish_stage_text(const claw_core_request_t *request, const char *text)
{
    (void)request;
    (void)text;
    return ESP_OK;
}

/* ---- helpers ---- */

#define SESSION "pairs"

static int s_call_seq;

static esp_err_t persist(claw_core_context_record_type_t type, const char *json, const char *text,
                         bool completed)
{
    claw_core_context_record_t record = {.type = type, .message_json = json, .text = text};
    claw_core_context_persist_batch_t batch = {
        .session_id = SESSION, .records = &record, .record_count = 1, .turn_completed = completed,
    };

    return claw_memory_persist_context_callback(&batch, NULL);
}

static esp_err_t persist_user(const char *text)
{
    return persist(CLAW_CORE_CONTEXT_RECORD_USER, NULL, text, false);
}

static esp_err_t persist_final(const char *text)
{
    return persist(CLAW_CORE_CONTEXT_RECORD_ASSISTANT_FINAL, NULL, text, true);
}

/* One tool round as the agent loop persists it: assistant tool_calls + all results in one batch. */
static esp_err_t persist_round(int calls, size_t output_bytes)
{
    cJSON *assistant = cJSON_CreateObject();
    cJSON *tool_calls = cJSON_AddArrayToObject(assistant, "tool_calls");
    cJSON *results = cJSON_CreateArray();
    char *output = malloc(output_bytes + 1);
    char *assistant_json;
    char *results_json;
    claw_core_context_record_t records[2];
    claw_core_context_persist_batch_t batch = {.session_id = SESSION, .records = records, .record_count = 2};
    esp_err_t err;
    size_t i;
    int c;

    /* Long ssh-like stdout with multi-byte characters. */
    for (i = 0; i + 3 <= output_bytes; i += 3) {
        memcpy(output + i, (i / 3) % 40 ? "ab\n" : "\xe2\x94\x80", 3);
    }
    output[i] = '\0';
    cJSON_AddStringToObject(assistant, "role", "assistant");
    cJSON_AddNullToObject(assistant, "content");
    for (c = 0; c < calls; c++) {
        char id[32];
        cJSON *call = cJSON_CreateObject();
        cJSON *function = cJSON_AddObjectToObject(call, "function");
        cJSON *result = cJSON_CreateObject();

        snprintf(id, sizeof(id), "call_%d", ++s_call_seq);
        cJSON_AddStringToObject(call, "id", id);
        cJSON_AddStringToObject(call, "type", "function");
        cJSON_AddStringToObject(function, "name", "ssh_exec");
        cJSON_AddStringToObject(function, "arguments", "{}");
        cJSON_AddItemToArray(tool_calls, call);
        cJSON_AddStringToObject(result, "role", "tool");
        cJSON_AddStringToObject(result, "tool_call_id", id);
        cJSON_AddStringToObject(result, "content", output);
        cJSON_AddFalseToObject(result, "is_error");
        cJSON_AddItemToArray(results, result);
    }
    assistant_json = cJSON_PrintUnformatted(assistant);
    results_json = cJSON_PrintUnformatted(results);
    records[0] = (claw_core_context_record_t) {.type = CLAW_CORE_CONTEXT_RECORD_ASSISTANT_TOOL,
                                               .message_json = assistant_json};
    records[1] = (claw_core_context_record_t) {.type = CLAW_CORE_CONTEXT_RECORD_TOOL_RESULT,
                                               .message_json = results_json};
    err = claw_memory_persist_context_callback(&batch, NULL);
    cJSON_free(assistant_json);
    cJSON_free(results_json);
    cJSON_Delete(assistant);
    cJSON_Delete(results);
    free(output);
    return err;
}

static const char *str(const cJSON *object, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);

    return cJSON_IsString(item) ? item->valuestring : NULL;
}

/* Every call answered right after it, every output preceded by its call. */
static int pairs_ok(const cJSON *messages, int *out_calls)
{
    int count = cJSON_GetArraySize(messages);
    int i = 0;

    *out_calls = 0;
    while (i < count) {
        const cJSON *message = cJSON_GetArrayItem(messages, i);
        const cJSON *calls = cJSON_GetObjectItemCaseSensitive(message, "tool_calls");
        const cJSON *call;
        int j = i + 1;

        if (str(message, "role") && strcmp(str(message, "role"), "tool") == 0) {
            fprintf(stderr, "orphan output %s at %d\n", str(message, "tool_call_id"), i);
            return 0;
        }
        if (cJSON_GetArraySize(calls) == 0) {
            i++;
            continue;
        }
        while (j < count && str(cJSON_GetArrayItem(messages, j), "role") &&
                strcmp(str(cJSON_GetArrayItem(messages, j), "role"), "tool") == 0) {
            j++;
        }
        if (j - i - 1 != cJSON_GetArraySize(calls)) {
            fprintf(stderr, "call/output count mismatch at %d\n", i);
            return 0;
        }
        cJSON_ArrayForEach(call, calls) {
            int k;
            int found = 0;

            for (k = i + 1; k < j; k++) {
                found |= strcmp(str(cJSON_GetArrayItem(messages, k), "tool_call_id"), str(call, "id")) == 0;
            }
            if (!found) {
                fprintf(stderr, "no tool output found for function call %s\n", str(call, "id"));
                return 0;
            }
            (*out_calls)++;
        }
        i = j;
    }
    return 1;
}

static int history_pairs_ok(int *out_calls)
{
    claw_core_request_t request = {.session_id = SESSION};
    claw_core_context_t context = {0};
    cJSON *messages;
    int ok;

    *out_calls = 0;
    if (claw_memory_session_history_provider.collect(&request, &context, NULL) != ESP_OK) {
        return 1; /* empty history is trivially paired */
    }
    messages = cJSON_Parse(context.content);
    ok = messages && pairs_ok(messages, out_calls);
    cJSON_Delete(messages);
    free(context.content);
    return ok;
}

static void reset_session(void)
{
    char *path = claw_memory_session_path_dup(SESSION);
    char *idx = dup_printf("%s.idx", path);
    char *blocked = dup_printf("%s.blocked", path);

    unlink(path);
    unlink(idx);
    unlink(blocked);
    free(path);
    free(idx);
    free(blocked);
}

/* ---- tests ---- */

/*
 * Reproduction of the bricked session: the large tool result write fails after the assistant
 * tool call record was written (disk full, reboot). The loaded history must not contain the call
 * without its output, and later turns must still load paired.
 */
static void test_failed_tool_result_write(void)
{
    int calls = 0;

    reset_session();
    CHECK(persist_user("check the server") == ESP_OK);
    s_fail_write_countdown = 1; /* assistant record succeeds, the tool result write fails */
    CHECK(persist_round(1, 8 * 1024) != ESP_OK);
    s_fail_write_countdown = -1;
    CHECK(persist_final("done") == ESP_OK);
    CHECK(persist_user("and now?") == ESP_OK);
    CHECK(history_pairs_ok(&calls));
    CHECK(persist_round(2, 2048) == ESP_OK);
    CHECK(persist_final("ok") == ESP_OK);
    CHECK(history_pairs_ok(&calls));
    CHECK(calls == 2);
}

/*
 * Long session with big outputs, parallel calls, interrupting user messages and unfinished turns:
 * size-limit compaction (on every completed turn) and summary compaction at many keep sizes must
 * always keep a tool call and its outputs together.
 */
static void test_trimming_keeps_whole_rounds(void)
{
    unsigned seed = 7;
    int turn;
    int calls = 0;
    int max_calls_seen = 0;
    int compactions = 0;
    size_t last_size = 0;

    reset_session();
    for (turn = 0; turn < 60; turn++) {
        int rounds = (int)((seed = seed * 1103515245u + 12345u) >> 16) % 4;
        int r;

        CHECK(persist_user("question") == ESP_OK);
        for (r = 0; r < rounds; r++) {
            int ncalls = 1 + (int)((seed = seed * 1103515245u + 12345u) >> 16) % 3;
            size_t size = 512 + ((seed = seed * 1103515245u + 12345u) >> 16) % (9 * 1024);

            CHECK(persist_round(ncalls, size) == ESP_OK);
            if (((seed = seed * 1103515245u + 12345u) >> 16) % 4 == 0) {
                CHECK(persist_user("interrupt while the tool ran") == ESP_OK);
            }
        }
        if (((seed = seed * 1103515245u + 12345u) >> 16) % 5) {
            CHECK(persist_final("answer") == ESP_OK);
        }
        CHECK(history_pairs_ok(&calls));
        {
            char *path = claw_memory_session_path_dup(SESSION);
            size_t size = file_size_bytes(path);

            compactions += size < last_size;
            last_size = size;
            free(path);
        }
        if (calls > max_calls_seen) {
            max_calls_seen = calls;
        }
    }
    CHECK(max_calls_seen > 0);
    CHECK(compactions > 0); /* the size limit compaction really ran */

    {
        char *path = claw_memory_session_path_dup(SESSION);
        char *idx = dup_printf("%s.idx", path);
        char *backup = dup_printf("%s.bak", path);
        char *backup_idx = dup_printf("%s.idx.bak", path);
        char cmd[1024];
        size_t keep;

        snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && cp '%s' '%s'", path, backup, idx, backup_idx);
        CHECK(system(cmd) == 0);
        for (keep = 1024; keep <= 160 * 1024; keep += 1536) {
            uint32_t dropped = 0;

            snprintf(cmd, sizeof(cmd), "cp '%s' '%s' && cp '%s' '%s'", backup, path, backup_idx, idx);
            CHECK(system(cmd) == 0);
            CHECK(claw_memory_session_compact_with_summary(path, keep, "summary", UINT32_MAX, &dropped) == ESP_OK);
            CHECK(keep > 32 * 1024 || dropped > 0);
            CHECK(history_pairs_ok(&calls));
        }
        unlink(backup);
        unlink(backup_idx);
        free(path);
        free(idx);
        free(backup);
        free(backup_idx);
    }
}

int main(void)
{
    char dir[] = "/tmp/claw_session_test_XXXXXX";

    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        return 2;
    }
    s_memory.initialized = 1;
    s_memory.max_message_chars = CLAW_MEMORY_DEFAULT_MAX_MESSAGE_CHARS;
    s_memory.backend_format = CLAW_MEMORY_BACKEND_FORMAT_UNKNOWN;
    snprintf(s_memory.session_root_dir, sizeof(s_memory.session_root_dir), "%s", dir);

    test_failed_tool_result_write();
    test_trimming_keeps_whole_rounds();

    reset_session();
    rmdir(dir);
    if (s_failures) {
        fprintf(stderr, "%d check(s) failed\n", s_failures);
        return 1;
    }
    printf("session tool pairing host tests passed\n");
    return 0;
}
