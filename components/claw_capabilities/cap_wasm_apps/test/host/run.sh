#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for the manifest rules (settings, timer/notify permissions, api) and the package code
# (formats 1 and 2, signatures, version order). Needs a C compiler and IDF_PATH (for cJSON and mbedTLS).
set -euo pipefail
cd "$(dirname "$0")"
: "${IDF_PATH:?export IDF_PATH (cJSON and mbedTLS are taken from \$IDF_PATH/components)}"
mbedtls="$IDF_PATH/components/mbedtls/mbedtls"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cc=("${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} -I ../../src -I "$IDF_PATH/components/json/cJSON")
"${cc[@]}" test_cap_wasm_manifest.c ../../src/cap_wasm_manifest.c "$IDF_PATH/components/json/cJSON/cJSON.c" \
    -o "$out/test_cap_wasm_manifest"
"$out/test_cap_wasm_manifest"
# Monocypher and mbedTLS are compiled with the project's warnings off: they are third-party code.
"${cc[@]}" -I ../../third_party/monocypher -I "$mbedtls/include" -I "$mbedtls/library" -Wno-unused-parameter \
    -Wno-implicit-fallthrough -Wno-sign-compare \
    test_cap_wasm_pkg.c ../../src/cap_wasm_pkg.c ../../src/cap_wasm_manifest.c "$IDF_PATH/components/json/cJSON/cJSON.c" \
    ../../third_party/monocypher/monocypher.c ../../third_party/monocypher/monocypher-ed25519.c \
    "$mbedtls/library/sha256.c" "$mbedtls/library/base64.c" "$mbedtls/library/platform_util.c" \
    "$mbedtls/library/constant_time.c" -o "$out/test_cap_wasm_pkg"
"$out/test_cap_wasm_pkg"
