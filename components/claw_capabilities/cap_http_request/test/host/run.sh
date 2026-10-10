#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for the redirect / read-only-POST rules. Needs a C compiler and IDF_PATH (for cJSON).
set -euo pipefail
cd "$(dirname "$0")"
: "${IDF_PATH:?export IDF_PATH (cJSON is taken from \$IDF_PATH/components/json/cJSON)}"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} \
    -I ../../include -I "$IDF_PATH/components/json/cJSON" \
    test_cap_http_rules.c ../../src/cap_http_rules.c "$IDF_PATH/components/json/cJSON/cJSON.c" \
    -o "$out/test_cap_http_rules"
"$out/test_cap_http_rules"
