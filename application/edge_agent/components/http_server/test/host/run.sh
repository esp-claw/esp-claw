#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for the web UI login tokens, sessions and LAN check (http_server_auth_core.c). Needs a C compiler.
set -euo pipefail
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} -I ../.. \
    test_http_server_auth_core.c ../../http_server_auth_core.c -o "$out/test_http_server_auth_core"
"$out/test_http_server_auth_core"
