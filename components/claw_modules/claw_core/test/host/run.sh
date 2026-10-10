#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for the tool call/output pairing repair and tool output clipping.
# Needs a C compiler and IDF_PATH (for cJSON).
set -euo pipefail
cd "$(dirname "$0")"
: "${IDF_PATH:?export IDF_PATH (cJSON is taken from \$IDF_PATH/components/json/cJSON)}"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} \
    -I ../../src -I "$IDF_PATH/components/json/cJSON" \
    test_claw_llm_history.c ../../src/llm/claw_llm_history.c "$IDF_PATH/components/json/cJSON/cJSON.c" \
    -o "$out/test_claw_llm_history"
"$out/test_claw_llm_history"
