/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host tests for the tool call/output pairing repair and the tool output clipping. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "llm/claw_llm_history.h"

static int s_failures;

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            s_failures++; \
        } \
    } while (0)

static const char *str(const cJSON *object, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);

    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static size_t call_ids(const cJSON *message, const char **ids, size_t cap)
{
    const cJSON *item;
    size_t n = 0;

    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(message, "tool_calls")) {
        if (str(item, "id") && n < cap) {
            ids[n++] = str(item, "id");
        }
    }
    item = cJSON_GetObjectItemCaseSensitive(message, "content");
    if (cJSON_IsArray(item)) {
        const cJSON *block;

        cJSON_ArrayForEach(block, item) {
            if (str(block, "type") && strcmp(str(block, "type"), "tool_use") == 0 && n < cap) {
                ids[n++] = str(block, "id");
            }
        }
    }
    return n;
}

/* The invariant every backend needs: each call answered exactly once, right after it, and nothing else. */
static int pairs_ok(const cJSON *messages)
{
    int count = cJSON_GetArraySize(messages);
    int i = 0;

    while (i < count) {
        const cJSON *message = cJSON_GetArrayItem(messages, i);
        const char *ids[16];
        int used[16] = {0};
        size_t n;
        size_t k;
        int j;

        if (str(message, "role") && strcmp(str(message, "role"), "tool") == 0) {
            return 0;
        }
        n = (str(message, "role") && strcmp(str(message, "role"), "assistant") == 0) ?
            call_ids(message, ids, 16) : 0;
        if (n == 0) {
            i++;
            continue;
        }
        for (j = i + 1; j < count; j++) {
            const cJSON *output = cJSON_GetArrayItem(messages, j);
            const char *id = str(output, "tool_call_id");
            int found = 0;

            if (!str(output, "role") || strcmp(str(output, "role"), "tool") != 0) {
                break;
            }
            for (k = 0; id && k < n; k++) {
                if (!used[k] && strcmp(ids[k], id) == 0) {
                    used[k] = 1;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                return 0;
            }
        }
        for (k = 0; k < n; k++) {
            if (!used[k]) {
                return 0;
            }
        }
        i = j;
    }
    return 1;
}

static cJSON *parse(const char *json)
{
    cJSON *messages = cJSON_Parse(json);

    if (!messages) {
        fprintf(stderr, "bad test JSON: %s\n", json);
        exit(2);
    }
    return messages;
}

static void test_orphan_call_from_device(void)
{
    /* The bricked Telegram session: a call whose output was lost, later turns, a new user message. */
    cJSON *m = parse("[{\"role\":\"user\",\"content\":\"check the server\"},"
                     "{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"call_13371\",\"type\":\"function\","
                     "\"function\":{\"name\":\"ssh_exec\",\"arguments\":\"{}\"}}]},"
                     "{\"role\":\"assistant\",\"content\":\"done\"},"
                     "{\"role\":\"user\",\"content\":\"and now?\"}]");
    claw_llm_tool_pair_repair_t stats;

    CHECK(!pairs_ok(m));
    CHECK(claw_llm_history_repair_tool_pairs(m, &stats));
    CHECK(stats.synthesized_outputs == 1 && stats.dropped_orphan_outputs == 0);
    CHECK(pairs_ok(m));
    CHECK(cJSON_GetArraySize(m) == 5);
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 2), "tool_call_id"), "call_13371") == 0);
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 2), "content"), CLAW_LLM_HISTORY_MISSING_TOOL_RESULT) == 0);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItem(cJSON_GetArrayItem(m, 2), "is_error")));
    cJSON_Delete(m);
}

static void test_partial_multi_result_and_strays(void)
{
    cJSON *m = parse("[{\"role\":\"tool\",\"tool_call_id\":\"x\",\"content\":\"stray at start\"},"
                     "{\"role\":\"user\",\"content\":\"u\"},"
                     "{\"role\":\"assistant\",\"tool_calls\":[{\"id\":\"a\",\"function\":{\"name\":\"t\"}},"
                     "{\"id\":\"b\",\"function\":{\"name\":\"t\"}},{\"id\":\"c\",\"function\":{\"name\":\"t\"}}]},"
                     "{\"role\":\"tool\",\"tool_call_id\":\"b\",\"content\":\"B\"},"
                     "{\"role\":\"tool\",\"tool_call_id\":\"zz\",\"content\":\"unknown id\"},"
                     "{\"role\":\"tool\",\"tool_call_id\":\"b\",\"content\":\"B again\"},"
                     "{\"role\":\"user\",\"content\":\"u2\"},"
                     "{\"role\":\"tool\",\"tool_call_id\":\"c\",\"content\":\"too late, not adjacent\"}]");
    claw_llm_tool_pair_repair_t stats;

    CHECK(claw_llm_history_repair_tool_pairs(m, &stats));
    CHECK(stats.synthesized_outputs == 2);
    CHECK(stats.dropped_orphan_outputs == 3);
    CHECK(stats.dropped_duplicate_outputs == 1);
    CHECK(pairs_ok(m));
    /* user, assistant, B, synthetic a, synthetic c, user */
    CHECK(cJSON_GetArraySize(m) == 6);
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 2), "content"), "B") == 0);
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 3), "tool_call_id"), "a") == 0);
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 4), "tool_call_id"), "c") == 0);
    cJSON_Delete(m);
}

static void test_anthropic_tool_use_blocks(void)
{
    cJSON *m = parse("[{\"role\":\"user\",\"content\":\"u\"},"
                     "{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"t\"},"
                     "{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"x\",\"input\":{}},"
                     "{\"type\":\"tool_use\",\"id\":\"toolu_2\",\"name\":\"x\",\"input\":{}}]},"
                     "{\"role\":\"tool\",\"tool_call_id\":\"toolu_2\",\"content\":\"ok\"}]");
    claw_llm_tool_pair_repair_t stats;

    CHECK(claw_llm_history_repair_tool_pairs(m, &stats));
    CHECK(stats.synthesized_outputs == 1 && stats.dropped_orphan_outputs == 0);
    CHECK(pairs_ok(m));
    CHECK(strcmp(str(cJSON_GetArrayItem(m, 3), "tool_call_id"), "toolu_1") == 0);
    cJSON_Delete(m);
}

static void test_valid_history_untouched(void)
{
    const char *json = "[{\"role\":\"user\",\"content\":\"u\"},"
                       "{\"role\":\"assistant\",\"content\":null,\"tool_calls\":[{\"id\":\"a\",\"function\":{\"name\":\"t\"}},"
                       "{\"id\":\"b\",\"function\":{\"name\":\"t\"}}]},"
                       "{\"role\":\"tool\",\"tool_call_id\":\"b\",\"content\":\"B\"},"
                       "{\"role\":\"tool\",\"tool_call_id\":\"a\",\"content\":\"A\"},"
                       "{\"role\":\"assistant\",\"content\":\"final\"}]";
    cJSON *m = parse(json);
    cJSON *orig = parse(json);
    claw_llm_tool_pair_repair_t stats;

    CHECK(claw_llm_history_repair_tool_pairs(m, &stats));
    CHECK(stats.synthesized_outputs == 0 && stats.dropped_orphan_outputs == 0 &&
          stats.dropped_duplicate_outputs == 0);
    CHECK(cJSON_Compare(m, orig, 1));
    cJSON_Delete(m);
    cJSON_Delete(orig);
}

/* Random histories with random records lost: the repaired array always satisfies the invariant. */
static void test_random_histories(void)
{
    unsigned seed = 12345;
    int round;

    for (round = 0; round < 2000; round++) {
        cJSON *m = cJSON_CreateArray();
        int turns = 1 + (int)((seed = seed * 1103515245u + 12345u) >> 16) % 6;
        int t;
        claw_llm_tool_pair_repair_t stats;

        for (t = 0; t < turns; t++) {
            int rounds = (int)((seed = seed * 1103515245u + 12345u) >> 16) % 3;
            int r;
            cJSON *user = cJSON_CreateObject();

            cJSON_AddStringToObject(user, "role", "user");
            cJSON_AddStringToObject(user, "content", "u");
            cJSON_AddItemToArray(m, user);
            for (r = 0; r < rounds; r++) {
                int calls = 1 + (int)((seed = seed * 1103515245u + 12345u) >> 16) % 3;
                cJSON *assistant = cJSON_CreateObject();
                cJSON *tc = cJSON_CreateArray();
                int c;

                cJSON_AddStringToObject(assistant, "role", "assistant");
                cJSON_AddItemToObject(assistant, "tool_calls", tc);
                for (c = 0; c < calls; c++) {
                    cJSON *call = cJSON_CreateObject();
                    char id[32];

                    snprintf(id, sizeof(id), "call_%d_%d_%d", t, r, c);
                    cJSON_AddStringToObject(call, "id", id);
                    cJSON_AddItemToArray(tc, call);
                }
                if (((seed = seed * 1103515245u + 12345u) >> 16) % 5) {
                    cJSON_AddItemToArray(m, assistant);
                } else {
                    cJSON_Delete(assistant); /* call lost, outputs stay: orphan outputs */
                }
                for (c = 0; c < calls; c++) {
                    char id[32];
                    cJSON *out;

                    if (((seed = seed * 1103515245u + 12345u) >> 16) % 4 == 0) {
                        continue; /* output lost */
                    }
                    snprintf(id, sizeof(id), "call_%d_%d_%d", t, r, c);
                    out = cJSON_CreateObject();
                    cJSON_AddStringToObject(out, "role", "tool");
                    cJSON_AddStringToObject(out, "tool_call_id", id);
                    cJSON_AddStringToObject(out, "content", "x");
                    cJSON_AddItemToArray(m, out);
                }
            }
            if (((seed = seed * 1103515245u + 12345u) >> 16) % 2) {
                cJSON *final = cJSON_CreateObject();

                cJSON_AddStringToObject(final, "role", "assistant");
                cJSON_AddStringToObject(final, "content", "f");
                cJSON_AddItemToArray(m, final);
            }
        }
        CHECK(claw_llm_history_repair_tool_pairs(m, &stats));
        CHECK(pairs_ok(m));
        cJSON_Delete(m);
    }
}

static int utf8_ok(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    while (*p) {
        int n = *p < 0x80 ? 1 : (*p >= 0xC2 && *p <= 0xDF) ? 2 : (*p >= 0xE0 && *p <= 0xEF) ? 3 :
                (*p >= 0xF0 && *p <= 0xF4) ? 4 : 0;
        int i;

        if (!n) {
            return 0;
        }
        for (i = 1; i < n; i++) {
            if ((p[i] & 0xC0) != 0x80) {
                return 0;
            }
        }
        p += n;
    }
    return 1;
}

static void test_clip_text(void)
{
    char short_text[] = "short output";
    char bad[] = "PDF \xe2\xe3\xcf\xd3 cut \xe2\x94";
    size_t len = 40000;
    char *big = malloc(len + 1);
    size_t i;

    CHECK(!claw_llm_history_clip_text(short_text, 100));
    CHECK(strcmp(short_text, "short output") == 0);

    CHECK(claw_llm_history_clip_text(bad, 100));
    CHECK(utf8_ok(bad));
    CHECK(strcmp(bad, "PDF ???? cut ??") == 0);

    /* Box drawing chars (3 bytes each) so any byte cut would split a character. */
    memcpy(big, "HEAD", 4);
    for (i = 4; i + 3 <= len - 4; i += 3) {
        memcpy(big + i, "\xe2\x94\x80", 3);
    }
    memcpy(big + i, "TAIL", 4);
    big[i + 4] = '\0';
    CHECK(claw_llm_history_clip_text(big, 16 * 1024));
    CHECK(strlen(big) <= 16 * 1024);
    CHECK(strncmp(big, "HEAD", 4) == 0);
    CHECK(strcmp(big + strlen(big) - 4, "TAIL") == 0);
    CHECK(strstr(big, "bytes truncated ...]") != NULL);
    CHECK(utf8_ok(big));
    free(big);
}

int main(void)
{
    test_orphan_call_from_device();
    test_partial_multi_result_and_strays();
    test_anthropic_tool_use_blocks();
    test_valid_history_untouched();
    test_random_histories();
    test_clip_text();
    if (s_failures) {
        fprintf(stderr, "%d check(s) failed\n", s_failures);
        return 1;
    }
    printf("claw_llm_history host tests passed\n");
    return 0;
}
