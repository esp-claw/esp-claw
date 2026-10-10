#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Host tests for the confirmation-eligibility rules (cap_im_tg_origin.c). Needs a C compiler.
set -euo pipefail
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g ${CFLAGS:-} \
    -I stubs -I ../../include -I ../../../../claw_modules/claw_cap/include -I ../../../../claw_modules/claw_core/include \
    test_cap_im_tg_origin.c ../../src/cap_im_tg_origin.c -o "$out/test_cap_im_tg_origin"
"$out/test_cap_im_tg_origin"
