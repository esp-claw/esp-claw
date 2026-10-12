#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g -pthread ${CFLAGS:-} \
    -I stubs -I ../../include \
    test_claw_storage_guard.c ../../src/claw_storage_guard.c \
    -o "$out/test_claw_storage_guard"
"$out/test_claw_storage_guard"
