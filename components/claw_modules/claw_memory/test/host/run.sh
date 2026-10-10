#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for session history persistence/compaction: tool calls and their outputs always
# survive together. Builds claw_memory_session.c unchanged against stubs/.
# Needs a C compiler and IDF_PATH (for cJSON).
set -euo pipefail
cd "$(dirname "$0")"
: "${IDF_PATH:?export IDF_PATH (cJSON is taken from \$IDF_PATH/components/json/cJSON)}"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} \
    -I stubs -I ../../src -I ../../include -I ../../../claw_core/include -I ../../../claw_core/src \
    -I "$IDF_PATH/components/json/cJSON" \
    test_session_tool_pairs.c ../../src/claw_memory_session.c "$IDF_PATH/components/json/cJSON/cJSON.c" \
    -o "$out/test_session_tool_pairs"
"$out/test_session_tool_pairs"
