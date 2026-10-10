# esp-claw WASM apps

Sandboxed apps that add LLM tools to the device. Each app is a freestanding WebAssembly module
run by WAMR's interpreter (`components/claw_capabilities/cap_wasm_apps`), with its own linear
memory, a per-call time budget and only the host functions its manifest grants.

```
apps/
  sdk/claw.h        host API v1 (import module "claw") + helper macros
  sdk/claw_util.h   optional output buffer / minimal JSON reader used by the examples
  hello/            echo, benchmark, persistent counter, runaway loop (runtime test app)
  cf_dns/           read-only Cloudflare DNS via the device's "cloudflare" API profile
  ping/             ICMP echo (ping) to a host from the device
  sdk/ecapp.py      packs and signs apps/<name>/build into an .ecapp package
  sdk/device_test.sh  install/update/remove test steps for a flashed device
  build.sh          builds apps/<name>/build/{app.wasm,manifest.json}
```

## Build

Needs clang with the wasm32 target and `wasm-ld` (`clang --print-targets | grep wasm32`;
Fedora: `dnf install clang lld`). `CC="zig cc"` works too.

```
apps/build.sh            # all apps
apps/build.sh hello      # one app
```

The linear memory is sized from `limits.memory_kb` in the manifest. Link errors about undefined
symbols mean the code needs something besides `claw.*` (e.g. libc's `memcpy` for a struct copy
the compiler could not turn into `memory.copy`): apps have no libc.

## Package and sign

Apps load only when signed by a key in the device config `app_trusted_keys` (JSON array of base64
raw 32-byte Ed25519 public keys; set `app_allow_unsigned` to `true` to also load unsigned apps
during development). Both are read at boot.

```
openssl genpkey -algorithm ed25519 -out key.pem      # once; keep it out of the repo
apps/sdk/ecapp.py pubkey key.pem                       # base64 public key for app_trusted_keys
apps/sdk/ecapp.py pack apps/hello/build --key key.pem # -> apps/hello/build/hello-1.0.0.ecapp
apps/sdk/ecapp.py verify apps/hello/build/hello-1.0.0.ecapp --pub <base64>
```

An `.ecapp` is `"ECAP"`, u8 format 1, u8 entry count 3, u16 0, then per entry u8 name length, name,
u32 little-endian length, data: `manifest.json`, `app.wasm`, `signature.json` (at most 4 KB, 256 KB,
1 KB; 512 KB in total). `signature.json`:

```json
{"alg":"ed25519","key_id":"<first 8 hex of sha256(public key)>","sdk":1,
 "signed":{"name":"hello","version":"1.0.0","manifest_sha256":"<hex>","wasm_sha256":"<hex>"},
 "sig":"<base64 Ed25519 signature>"}
```

`sig` signs the canonical bytes of `signed`: keys in exactly that order, no whitespace, lowercase
hex, i.e. `{"name":"hello","version":"1.0.0","manifest_sha256":"…","wasm_sha256":"…"}`. The device
checks the format, `sdk` (1), name and version against the manifest, both hashes, that `key_id` is
trusted, and the signature (Monocypher's Ed25519) on install and on every load. Versions are
`MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` and ordered like semver.

## Install on the device

Host the `.ecapp` on any https URL (e.g. a GitHub release), then in Telegram:

```
/app install <https-url>            download (<= 512 KB), verify, confirm, install
/app install --force <https-url>    same, but allows a lower version than installed
/app update <name> [https-url]      update; without a URL from where it was installed
/app remove <name>                  delete the app, its files and its key-value data
/apps                               list: version, state, key, PSRAM, last use, tools, last error
/apps enable|disable <name>         persisted in apps/index.json; disabled apps have no tools
/apps load|unload <name>            load into / free from memory now
/apps reload <name>                 reload from <storage>/apps/<name>/
```

Install and remove always ask for confirmation in the chat (✅ Installieren / ❌ Abbrechen), also
when the LLM calls `apps_install(url)` or `apps_remove(name)`; callers outside Telegram are refused.
The new version is staged in `apps/<name>.new/`; the old one is kept as `apps/<name>.old/` until the
new one loaded and restored otherwise (also after a reboot in between). `apps/index.json` records
name, version, key, enabled/disabled, install time and source URL.

LLM tools: `apps_status`, `apps_load(name)`, `apps_unload(name)`, `apps_set_enabled(name, enabled)`
(no confirmation), `apps_install(url)`, `apps_remove(name)`.

Copying files to `<storage>/apps/<name>/` by WebDAV or the files API still works for signed apps
(include `signature.json`) followed by `/apps reload <name>`; unsigned ones show as `unsigned`.
`apps/sdk/device_test.sh` walks through the whole flow on a flashed device.

## Memory: on-demand loading

At boot, enabled and validly signed apps register their tools from `apps/<name>/tools.json` (the
tool list of their last successful `app_init`, bound to the wasm hash) without being loaded. The
first call loads the app (logged with its load time); it is unloaded again after 10 minutes without
calls, and the least recently used apps are unloaded when a load would leave less than 1 MB of PSRAM
free. An app with a call in progress is never unloaded. If an app registers different tools than
cached, the cache is refreshed and the tools re-registered.

## manifest.json

```json
{
  "name": "cf_dns",
  "version": "1.0.0",
  "description": "shown in /apps and apps_status",
  "permissions": { "log": true, "kv": true, "http_profiles": ["cloudflare"], "confirm": true, "ping": true },
  "limits": { "memory_kb": 64, "call_timeout_ms": 5000 }
}
```

| field | rule |
|---|---|
| `name` | required, 1-24 chars `[a-z0-9_]`, starts with a letter, equals the directory name |
| `version` | required, 1-16 chars `[A-Za-z0-9.+-]` |
| `description` | optional, <= 200 bytes |
| `permissions.log` / `kv` / `confirm` / `ping` | optional booleans, default false |
| `permissions.http_profiles` | optional, 1-4 names of `api_profiles` entries the app may use |
| `limits.memory_kb` | linear memory cap, multiple of 64, 64-512, default 64 |
| `limits.call_timeout_ms` | budget per tool call, 100-30000, default 5000 (`app_init`: fixed 2000) |

Unknown keys or permissions reject the app. So does importing a host function whose permission
the manifest does not grant, or any import outside `claw.*` (checked at load, before the app runs).

## App contract

Exports: `app_init()` registers tools with `claw_tool_register()`; `app_alloc(size)` returns a
buffer for the next call's argument JSON (`CLAW_DEFINE_ARENA()` provides one); `tool_call(tool,
args, len)` handles a call, sets the result with `claw_tool_result()` and returns 0.

Tools appear to the LLM as `<app>_<tool>` in capability group `cap_wasm_apps`, which is LLM-visible
by default (if `llm_visible_cap_groups` is set explicitly, add `cap_wasm_apps`; the management tools
in `cap_wasm_apps_mgr` follow it). At most 32 app
tools in total.

## Runtime limits

- Each tool call runs under `limits.call_timeout_ms` of wall-clock time (time blocked in HTTP
  requests or Telegram confirmations does not count). When it runs out the call is stopped, the
  instance is discarded and recreated on the next call (`app_init` runs again and must register
  the same tools). After 3 consecutive traps/timeouts the app is disabled until `/apps reload` or
  reboot.
- An app that crashed the device while being loaded at boot is skipped on the next boot
  (`.loading` marker); `/apps reload <name>` retries it.
- Loading is refused when it would leave less than 1 MB of PSRAM free even after unloading every
  other app.
- Results <= 16 KB, HTTP responses <= 32 KB, key-value values <= 1 KB / 32 keys per app / 16 writes
  per call, 32 log lines per call.
- Do not export `__heap_base`/`__data_end`/`__stack_pointer`: WAMR would then split the app's stack
  between (unused) threads and halve it.
