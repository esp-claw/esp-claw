/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"

#define CLAW_LLM_HISTORY_MISSING_TOOL_RESULT "[tool result unavailable: interrupted or truncated]"

typedef struct {
    size_t synthesized_outputs;   /* calls without an output: synthetic output inserted */
    size_t dropped_orphan_outputs; /* outputs without a matching preceding call */
    size_t dropped_duplicate_outputs;
} claw_llm_tool_pair_repair_t;

/*
 * Makes a Chat Completions style message array safe to send: every assistant
 * tool call (tool_calls[].id or an Anthropic tool_use block) is followed by
 * exactly one "tool" message with its id, in the run of tool messages that
 * directly follows the assistant message. Missing outputs get a synthetic
 * error output, tool messages without a matching call are removed.
 * Returns false only when out of memory (the array is then left consistent
 * up to the failing point).
 */
bool claw_llm_history_repair_tool_pairs(cJSON *messages, claw_llm_tool_pair_repair_t *out_stats);

/*
 * In place: replaces invalid UTF-8 bytes with '?' and, when the text is longer
 * than max_bytes, keeps its head and tail around a "[... N bytes truncated ...]"
 * marker (cut on UTF-8 boundaries). Returns true when the text was changed.
 */
bool claw_llm_history_clip_text(char *text, size_t max_bytes);
