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

## Install on the device

Copy `manifest.json` and `app.wasm` to `<storage>/apps/<name>/` (`/fatfs/apps/<name>/`), then
send `/apps reload <name>` in Telegram (or reboot). The directory name must equal the manifest name.

WebDAV (needs `webdav_password`; `dav://<ip>/dav/apps/<name>/` in a file manager):

```
curl -u "$DAV_USER:$DAV_PASS" -X MKCOL http://<ip>/dav/apps/
curl -u "$DAV_USER:$DAV_PASS" -X MKCOL http://<ip>/dav/apps/hello/
curl -u "$DAV_USER:$DAV_PASS" -T apps/hello/build/manifest.json http://<ip>/dav/apps/hello/manifest.json
curl -u "$DAV_USER:$DAV_PASS" -T apps/hello/build/app.wasm      http://<ip>/dav/apps/hello/app.wasm
```

Files API:

```
curl -X POST http://<ip>/api/files/mkdir -d '{"path":"/apps/hello","recursive":true}'
curl -X POST --data-binary @apps/hello/build/manifest.json "http://<ip>/api/files/upload?path=/apps/hello/manifest.json"
curl -X POST --data-binary @apps/hello/build/app.wasm      "http://<ip>/api/files/upload?path=/apps/hello/app.wasm"
```

Telegram: `/apps` lists apps (version, state, tools, memory, last error), `/apps reload <name>`
(re)loads one from storage, `/apps disable <name>` unloads it until reload or reboot. The LLM
tool `apps_status` returns the same as JSON.

## manifest.json

```json
{
  "name": "cf_dns",
  "version": "1.0.0",
  "description": "shown in /apps and apps_status",
  "permissions": { "log": true, "kv": true, "http_profiles": ["cloudflare"], "confirm": true },
  "limits": { "memory_kb": 64, "call_timeout_ms": 5000 }
}
```

| field | rule |
|---|---|
| `name` | required, 1-24 chars `[a-z0-9_]`, starts with a letter, equals the directory name |
| `version` | required, 1-16 chars `[A-Za-z0-9.+-]` |
| `description` | optional, <= 200 bytes |
| `permissions.log` / `kv` / `confirm` | optional booleans, default false |
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
by default (if `llm_visible_cap_groups` is set explicitly, add `cap_wasm_apps`). At most 32 app
tools in total.

## Runtime limits

- Each tool call runs under `limits.call_timeout_ms` of wall-clock time (time blocked in HTTP
  requests or Telegram confirmations does not count). When it runs out the call is stopped, the
  instance is discarded and recreated on the next call (`app_init` runs again and must register
  the same tools). After 3 consecutive traps/timeouts the app is disabled until `/apps reload` or
  reboot.
- An app that crashed the device while loading is skipped on the next boot (`.loading` marker);
  `/apps reload <name>` retries it.
- Loading is refused when it would leave less than 1 MB of PSRAM free.
- Results <= 16 KB, HTTP responses <= 32 KB, key-value values <= 1 KB / 32 keys per app / 16 writes
  per call, 32 log lines per call.
- Do not export `__heap_base`/`__data_end`/`__stack_pointer`: WAMR would then split the app's stack
  between (unused) threads and halve it.
