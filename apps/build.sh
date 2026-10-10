#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
# Builds esp-claw WASM apps: apps/build.sh [app ...] (default: every dir with a manifest.json).
# Output: apps/<app>/build/{app.wasm,manifest.json}. Needs clang with the wasm32 target and wasm-ld
# (`clang --print-targets | grep wasm32`); set CC=... to use another clang (or `zig cc`).
set -euo pipefail
cd "$(dirname "$0")"
CC=${CC:-clang}

apps=("$@")
if [ ${#apps[@]} -eq 0 ]; then
    for m in */manifest.json; do apps+=("$(dirname "$m")"); done
fi

for app in "${apps[@]}"; do
    # The linear memory is sized to limits.memory_kb so the runtime cap and the module agree.
    mem_kb=$(sed -n 's/.*"memory_kb"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$app/manifest.json")
    mem=$(( ${mem_kb:-64} * 1024 ))
    mkdir -p "$app/build"
    # -mcpu=mvp -mbulk-memory: features WAMR's interpreter is built with (memcpy -> memory.copy).
    # No --allow-undefined: anything but a claw.* import is a link error, not a runtime rejection.
    "$CC" --target=wasm32 -mcpu=mvp -mbulk-memory -O2 -nostdlib -ffreestanding -Wall -Wextra \
        -I sdk/include -Wl,--no-entry -Wl,--strip-all \
        -Wl,--export=app_init -Wl,--export=app_alloc -Wl,--export=tool_call \
        -Wl,--initial-memory=$mem -Wl,--max-memory=$mem -Wl,-z,stack-size=8192 \
        -o "$app/build/app.wasm" "$app"/*.c
    cp "$app/manifest.json" "$app/build/manifest.json"
    echo "$app: $(stat -c %s "$app/build/app.wasm") bytes, memory ${mem_kb:-64} KB"
done
