#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: Apache-2.0
#
# Device test for signed WASM app installs, after flashing:
#
#   apps/sdk/device_test.sh setup <device-ip> <ed25519.pem>   trust the key, upload an unsigned app, reboot
#   apps/sdk/device_test.sh serve <ed25519.pem>               build test packages and serve them over https
#   apps/sdk/device_test.sh check <device-ip>                 show apps/index.json and the cached tool lists
#
# `serve` needs `cloudflared` (quick tunnel) or BASE_URL=https://... pointing at a host where you
# upload the files it prints. It then lists the Telegram steps with their expected results.
# Needs apps built (apps/build.sh). The private key is only passed to ecapp.py, never printed.
set -euo pipefail
APPS=$(cd "$(dirname "$0")/.." && pwd)
ECAPP="python3 $APPS/sdk/tools/ecapp.py"
OUT=${OUT:-/tmp/ecapp-device-test}
PORT=${PORT:-8765}

wait_up() {
    for _ in $(seq 60); do
        curl -fsS -m 2 "http://$1/api/status" >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "device $1 did not come back" >&2
    exit 1
}

setup() {
    local ip=$1 pem=$2 pub
    pub=$($ECAPP pubkey "$pem" | cut -d' ' -f1)
    curl -fsS -X POST "http://$ip/api/config" -H 'Content-Type: application/json' \
        -d "{\"app_trusted_keys\":\"[\\\"$pub\\\"]\",\"app_allow_unsigned\":\"false\"}"
    echo
    # An unsigned copy of ping must show up as "unsigned" and not load.
    curl -fsS -X POST "http://$ip/api/files/mkdir" -d '{"path":"/apps/ping","recursive":true}' >/dev/null
    for f in manifest.json app.wasm; do
        curl -fsS -X POST --data-binary "@$APPS/ping/build/$f" "http://$ip/api/files/upload?path=/apps/ping/$f" >/dev/null
    done
    curl -fsS -X POST "http://$ip/api/restart" >/dev/null || true
    sleep 5
    wait_up "$ip"
    echo "Trusted key $pub; unsigned ping uploaded; device rebooted."
    echo "Telegram: /apps  ->  ping ... unsigned, last error: not loaded: no signature.json"
}

serve() {
    local pem=$1 base
    rm -rf "$OUT" && mkdir -p "$OUT/src"
    for app in hello cf_dns ping; do
        $ECAPP pack "$APPS/$app/build" --key "$pem" -o "$OUT/$app.ecapp" >/dev/null
    done
    # Same code, other versions: an update and a downgrade.
    for v in 1.0.1 0.9.0; do
        mkdir -p "$OUT/src/$v" && cp "$APPS/hello/build/app.wasm" "$OUT/src/$v/"
        sed "s/\"version\": *\"[^\"]*\"/\"version\": \"$v\"/" "$APPS/hello/build/manifest.json" > "$OUT/src/$v/manifest.json"
        $ECAPP pack "$OUT/src/$v" --key "$pem" -o "$OUT/hello-$v.ecapp" >/dev/null
    done
    # Signed package whose app.wasm was changed afterwards.
    python3 - "$OUT/hello.ecapp" "$OUT/tampered.ecapp" <<'EOF'
import sys
blob = bytearray(open(sys.argv[1], "rb").read())
i = blob.index(b"\x00asm")
blob[i + 20] ^= 1
open(sys.argv[2], "wb").write(blob)
EOF
    rm -rf "$OUT/src"
    if [ -n "${BASE_URL:-}" ]; then
        base=$BASE_URL
        echo "Upload these files to $base/:"; ls -1 "$OUT"
    else
        command -v cloudflared >/dev/null || { echo "need cloudflared or BASE_URL" >&2; exit 1; }
        (cd "$OUT" && python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1) &
        cloudflared tunnel --url "http://127.0.0.1:$PORT" > "$OUT.tunnel.log" 2>&1 &
        trap 'kill $(jobs -p) 2>/dev/null' EXIT
        for _ in $(seq 30); do
            base=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$OUT.tunnel.log" | head -1 || true)
            [ -n "$base" ] && break
            sleep 1
        done
        [ -n "$base" ] || { echo "no tunnel URL, see $OUT.tunnel.log" >&2; exit 1; }
    fi
    cat <<EOF

Telegram steps (each install/remove shows a confirmation; press the button unless noted):
 1. /app install $base/tampered.ecapp      -> Error: package rejected: app.wasm does not match its signed hash
 2. /app install $base/hello.ecapp         -> Installed \`hello\` 1.0.0: 4 tools.
 3. Ask: "call hello_echo with text hi"    -> {"echo":"hi","len":2}
    /apps                                  -> hello 1.0.0 — loaded, psram ... KB, key 7087d6a8 ...
 4. /app install $base/hello-0.9.0.ecapp   -> Error: hello 0.9.0 is older than the installed 1.0.0 ...
 5. /app install --force $base/hello-0.9.0.ecapp -> confirmation shows "⚠️ Downgrade"; press ❌ -> Not installed: cancelled
 6. /app update hello $base/hello-1.0.1.ecapp    -> Installed \`hello\` 1.0.1: 4 tools.
 7. /app update hello                      -> confirmation for 1.0.1 again (URL from index.json); press ❌
 8. /app install $base/ping.ecapp          -> replaces the unsigned ping: Installed \`ping\` 1.0.0: 1 tools.
 9. /apps disable hello, then reboot (curl -X POST http://<ip>/api/restart)
    /apps                                  -> hello disabled; the agent no longer sees hello_* tools
    /apps enable hello                     -> Enabled \`hello\` 1.0.1: 4 tools.
10. After that reboot: /apps shows hello/ping "unloaded" (tools registered from tools.json).
    Ask: "call ping_host for 1.1.1.1"      -> works; log: "[ping] v1.0.0 loaded on demand in N ms"
11. Ask the agent to use apps_status, apps_unload(ping), apps_load(ping), apps_set_enabled(hello,false/true)
                                           -> no confirmation; apps_status shows loaded/psram_bytes/last_used_s_ago
12. Leave ping loaded 10 min without calls -> log: "[ping] unloaded after 10 min without calls"
13. Ask: "install $base/cf_dns.ecapp"      -> agent calls apps_install, confirmation appears in the chat
14. /app remove cf_dns                     -> confirm -> Removed \`cf_dns\`.
15. apps/sdk/device_test.sh check <ip>     -> index.json lists hello (1.0.1, enabled) and ping, not cf_dns

Serving $OUT at $base (Ctrl-C to stop).
EOF
    [ -n "${BASE_URL:-}" ] || wait
}

check() {
    local ip=$1
    curl -fsS "http://$ip/files/apps/index.json"; echo
    for app in hello cf_dns ping; do
        echo "--- $app/tools.json"
        curl -fsS "http://$ip/files/apps/$app/tools.json" | head -c 400 || echo "(none)"
        echo
    done
}

case "${1:-}" in
    setup) setup "$2" "$3" ;;
    serve) serve "$2" ;;
    check) check "$2" ;;
    *) sed -n '5,12p' "$0"; exit 1 ;;
esac
