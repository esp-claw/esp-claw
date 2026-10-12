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
cjson_dir="$IDF_PATH/components/json/cJSON"
if [[ ! -f "$cjson_dir/cJSON.c" ]]; then
    cjson_dir="$IDF_PATH/managed_components/espressif__cjson"
fi
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} \
    -I stubs -I ../../src -I ../../include -I ../../../claw_core/include -I ../../../claw_core/src \
    -I "$cjson_dir" \
    test_session_tool_pairs.c ../../src/claw_memory_session.c "$cjson_dir/cJSON.c" \
    -o "$out/test_session_tool_pairs"
"$out/test_session_tool_pairs"

"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g -ffunction-sections -fdata-sections ${CFLAGS:-} \
    -I stubs -I ../../src -I ../../include -I ../../../claw_core/include -I ../../../claw_core/src \
    -I "$cjson_dir" \
    test_memory_index_recovery.c ../../src/claw_memory_storage.c ../../src/claw_memory_records.c \
    ../../src/claw_memory_utils.c \
    ../../src/claw_memory_algo.c ../../src/claw_memory_extract.c "$cjson_dir/cJSON.c" \
    -Wl,--gc-sections -Wl,--wrap=fopen -Wl,--wrap=fclose -Wl,--wrap=rename \
    -o "$out/test_memory_index_recovery"
"$out/test_memory_index_recovery"
