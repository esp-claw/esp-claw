#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cjson_dir="${IDF_PATH:-}/components/json/cJSON"
if [[ ! -f "$cjson_dir/cJSON.c" ]]; then
    cjson_dir="../../../../../application/edge_agent/managed_components/espressif__cjson/cJSON"
fi
"${CC:-cc}" -std=gnu11 -Wall -Wextra -Werror -g -pthread \
    -DCAP_SYSTEM_STORAGE_HOST_TEST \
    -I stubs -I ../../include \
    -I ../../../../claw_modules/claw_cap/include \
    -I ../../../../claw_modules/claw_core/include \
    -I "$cjson_dir" \
    test_cap_system_storage.c ../../src/cap_system_storage.c \
    "$cjson_dir/cJSON.c" \
    -lm -o "$out/test_cap_system_storage"
"$out/test_cap_system_storage"
