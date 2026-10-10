/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Pure helpers of the memory pipeline (no ESP-IDF dependencies besides cJSON),
 * so scoring, parsing and filtering can be unit-tested on the host. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"

#define CLAW_MEMORY_EMBED_DIM        256
#define CLAW_MEMORY_TOKEN_MAX        24
#define CLAW_MEMORY_QUERY_MAX_TOKENS 12
#define CLAW_MEMORY_FACTS_MAX        8
#define CLAW_MEMORY_RECONCILE_TOPK   5
#define CLAW_MEMORY_ID_MAX           40

typedef enum {
    CLAW_MEMORY_KIND_OTHER = 0,
    CLAW_MEMORY_KIND_PROFILE,
    CLAW_MEMORY_KIND_PREFERENCE,
    CLAW_MEMORY_KIND_DEVICE,
    CLAW_MEMORY_KIND_PROJECT,
    CLAW_MEMORY_KIND_EVENT,
} claw_memory_kind_t;

typedef struct {
    char content[256];
    char tags[96];
    char keywords[128];
    uint8_t importance;
    uint8_t kind;
} claw_memory_fact_t;

typedef enum {
    CLAW_MEMORY_OP_ADD = 0,
    CLAW_MEMORY_OP_UPDATE,
    CLAW_MEMORY_OP_DELETE,
    CLAW_MEMORY_OP_NOOP,
} claw_memory_op_t;

typedef struct {
    uint8_t op;
    char id[CLAW_MEMORY_ID_MAX];
    char content[256];
} claw_memory_decision_t;

#define CLAW_MEMORY_MIN_VALID_EPOCH       1704067200U /* 2024-01-01 */
#define CLAW_MEMORY_GC_MAX_AGE_SEC        (30U * 86400U)
#define CLAW_MEMORY_GC_COMPACT_BYTES      (128U * 1024U)
#define CLAW_MEMORY_GC_KEEP_BYTES         (48U * 1024U)
#define CLAW_MEMORY_GC_BUDGET_BYTES       (512U * 1024U)

typedef struct {
    uint32_t bytes;     /* all files of the session (.log, .idx, .skills.json) */
    uint32_t log_bytes; /* .log only */
    uint32_t mtime;     /* last write of the .log */
    bool active;        /* current session of a chat */
    bool extracted;     /* nothing left for the memory pipeline */
} claw_memory_gc_entry_t;

typedef enum {
    CLAW_MEMORY_GC_KEEP = 0,
    CLAW_MEMORY_GC_DELETE,
    CLAW_MEMORY_GC_COMPACT,
} claw_memory_gc_action_t;

/* Session storage GC plan:
 * 1. inactive + extracted + older than 30 days (valid clock and mtime) -> delete
 * 2. .log larger than 128 KB -> compact to the newest 48 KB
 * 3. over the 512 KB budget -> delete the oldest inactive extracted sessions,
 *    then compact the largest remaining logs.
 * fixed_bytes counts files that are not sessions (maps). Returns the projected
 * total size after the plan. */
uint32_t claw_memory_gc_plan(const claw_memory_gc_entry_t *entries,
                             size_t count,
                             uint32_t now,
                             uint32_t fixed_bytes,
                             uint8_t *out_actions);

const char *claw_memory_kind_name(uint8_t kind);
uint8_t claw_memory_kind_from_name(const char *name);

/* True when text looks like it carries a credential (API keys, tokens, passwords). */
bool claw_memory_text_has_secret(const char *text);

/* Start offset of the kept tail when text must shrink to max_bytes: lands on a
 * UTF-8 boundary and, when one is close, right after a newline. 0 if it fits. */
size_t claw_memory_tail_offset(const char *text, size_t len, size_t max_bytes);

/* Lower-cased retrieval tokens of a free-text query; stop words and 1-char
 * tokens are dropped. Returns the number of tokens written. */
size_t claw_memory_tokenize(const char *text,
                            char tokens[][CLAW_MEMORY_TOKEN_MAX],
                            size_t max_tokens);

/* 0..1: share of query tokens found in keywords/tags (full weight) or content. */
float claw_memory_keyword_match(const char tokens[][CLAW_MEMORY_TOKEN_MAX],
                                size_t token_count,
                                const char *content,
                                const char *tags,
                                const char *keywords);

/* 0.6 * cosine + 0.4 * keyword when a cosine is available, keyword otherwise. */
float claw_memory_hybrid_match(float cosine, float keyword, bool has_cosine);

/* match x recency (30 day half-life) x usage (log access count) x importance. */
float claw_memory_rank_score(float match,
                             uint32_t now,
                             uint32_t updated_at,
                             uint16_t access_count,
                             uint8_t importance);

void claw_memory_vec_quantize(const float *vec, int8_t *out, float *out_scale);
void claw_memory_vec_dequantize(const int8_t *vec, float scale, float *out);
float claw_memory_vec_cosine(const int8_t *stored, const float *query);

/* Parses {"facts":[...]} from the extraction LLM. Candidates with secrets or
 * without content are dropped (counted in out_dropped). */
size_t claw_memory_parse_facts(const cJSON *root,
                               claw_memory_fact_t *out,
                               size_t max_facts,
                               size_t *out_dropped);

/* Parses {"decisions":[...]} from the reconcile LLM into one decision per
 * candidate. UPDATE/DELETE must name one of that candidate's neighbors;
 * unknown ids degrade to ADD (update) or NOOP (delete). Missing entries ADD. */
void claw_memory_parse_decisions(const cJSON *root,
                                 size_t candidate_count,
                                 const char (*neighbors)[CLAW_MEMORY_RECONCILE_TOPK][CLAW_MEMORY_ID_MAX],
                                 const claw_memory_fact_t *candidates,
                                 claw_memory_decision_t *out);
