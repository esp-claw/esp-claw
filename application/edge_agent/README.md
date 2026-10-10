# Edge Agent Guide

## FATFS Image Layout

Source content for all FAT partitions lives under a single tree, with one
subdirectory per partition:

```text
application/edge_agent/fatfs_image/
├── storage/   # → storage partition (writable, mounted at /fatfs)
└── system/    # → system partition (read-only seed, mounted at /system)
```

Each subdirectory is copied into its own build-time staging directory:

```text
application/edge_agent/build/fatfs_image/        # storage staging
application/edge_agent/build/system_fs_image/    # system staging
```

Each board can also provide optional board-specific FATFS content under its own board directory. This content is overlaid onto the `system` partition:

```text
application/edge_agent/boards/<vendor>/<board>/fatfs_image/
```

During the build, `application/edge_agent/CMakeLists.txt` first copies the base `fatfs_image/system/` directory into the system staging dir, then copies the selected board's `fatfs_image/` directory if it exists. The selected board path comes from the generated `components/gen_bmgr_codes/CMakeLists.txt`, which is produced by `idf.py bmgr`.

If a board-specific file has the same relative path as a base system file, the board-specific file overwrites the base file in `build/system_fs_image/`. This lets a board replace firmware-baked defaults such as skills, scripts, and static assets without changing the shared base image. Board `fatfs_image/` content targets the SYSTEM image only; hidden board folders are not considered.

Skill manifests and built-in Lua scripts/docs are synced into `build/system_fs_image/` so they end up on the read-only system partition; the writable storage partition can be reformatted at runtime and re-seeded from `/system` without losing them.

With `CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED` (set by `esp32_S3_DevKitC_1`) there is no system
partition: `tools/pack_system_fs.py` packs the system staging dir, without `fonts/`, into
`build/system_fs.bin`, which is embedded in the app and served read-only at `/system` by
`main/app_romfs.c`. Paths stay the same, and an OTA update replaces these files together with the
firmware.

## Firmware updates (OTA)

Boards with `partitions_8MB_ota.csv` have two app slots and `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`.
`/fw` in Telegram (or the `firmware_status` / `firmware_check` / `firmware_update` tools) installs
signed images. Default source: the latest release of `esp-claw/esp-claw` with the assets
`edge_agent.bin` (built by `.github/workflows/firmware_release.yml` on a `vX.Y.Z` tag) and
`edge_agent.bin.sig.json` (made with `tools/fwsign.py sign edge_agent.bin --key <ed25519.pem>` by a
key listed in `app_trusted_keys`). `/fw update <url>` takes any https `.bin` with `<url>.sig.json`
next to it. A new image must have WiFi and Telegram working within 5 minutes and run for 60 s,
otherwise the device rolls back to the previous one. Moving an existing board to this layout
keeps NVS and `/fatfs`: `tools/migrate_ota_layout.sh -p <port>`.

`/updates` (or `/app updates`, the `apps_check_updates` tool) compares the firmware and every app
installed from a GitHub release URL with the latest release of its repository; `/app update <name>`
and `/app update all` (the `apps_update` tool) install them after a confirmation. Every day at
`update_check_time` (local time, default `09:00`, empty turns it off) the device runs that check
and tells the allowed Telegram users about new versions, at most once a week per version. It never
installs anything by itself.

## Web UI access

The web UI, `/api` and WebDAV are served over HTTPS (port 443) with a self-signed ECDSA certificate
that the device creates on first start (stored in NVS). Only clients in the STA or setup-AP subnet
can connect. Once a Telegram bot token and `tg_allowed_user_ids` are configured (read at boot),
the UI needs a login: send `/web` to the bot and open the one-time link (5 minutes, single use);
the session lasts 12 hours (at most 4, kept in RAM). `/web` also prints the certificate's SHA-256
fingerprint to compare with the browser warning; `/web status` lists URLs and sessions, and
`/web cert renew` issues a certificate for the current IP addresses. Port 80 redirects to HTTPS,
except for the setup portal on the soft-AP while no login is possible: before Telegram is set up,
or while the STA is down and the AP has a password. WebDAV is only available as `davs://<ip>/dav/`.


## Quick Start

### Prerequisites

- ESP-IDF is installed and exported
- `ESP-IDF v5.5.4` is recommended

```bash
. <your-esp-idf-path>/export.sh
```

### Configuration

To make `esp-board-manager` easier to use, first install the helper package with `pip install esp-bmgr-assist`. You only need to do this once in a given ESP-IDF environment.

1. Generate board support files:

```bash
cd application/edge_agent
idf.py bmgr -c ./boards -b esp32_S3_DevKitC_1
```

> `idf.py bmgr -c ./boards -b <board_name>` generates the configuration for the specified board. Available board names can be found in the `boards` directory.

2. Configure Wi-Fi, LLM, IM, search engine, and related parameters:

The key demo settings include:

- Wi-Fi SSID / Password
- LLM API Key / Provider / Model
- QQ App ID / App Secret
- Telegram Bot Token
- Brave / Tavily Search Key
- Timezone

Key Notes:

- IM bot token: available from Telegram [@BotFather](https://t.me/BotFather) or [QQ Bot](https://q.qq.com/qqbot/openclaw/login.html)
- LLM API key: available from [Anthropic Console](https://console.anthropic.com), [OpenAI Platform](https://platform.openai.com), or [Alibaba Cloud Bailian](https://bailian.console.aliyun.com/#/api-key)

You can adjust compile-time default values through `menuconfig`:

```bash
idf.py menuconfig
```

3. Build and flash:

```bash
idf.py build
idf.py flash monitor
```

## API credential profiles (`api_profiles`)

`api_profiles` (device config, JSON array, at most 3583 bytes) holds credentials that `http_request`
(with `"profile"`) and WASM apps use without ever seeing the secret (apps: see
https://github.com/esp-claw/app-sdk and https://github.com/esp-claw/app-template):

```json
[
  {"name": "cloudflare", "base_url": "https://api.cloudflare.com/client/v4",
   "hosts": ["api.cloudflare.com"], "auth": {"type": "bearer", "token": "..."},
   "read_only_posts": ["/graphql"]},
  {"name": "brave", "base_url": "https://api.search.brave.com", "hosts": ["api.search.brave.com"],
   "auth": {"type": "header", "name": "X-Subscription-Token", "value": "..."}}
]
```

- `auth.type` is `bearer` (`token`), `header` (`name`, `value`) or `google_service_account`
  (`json`, `scopes`).
- `hosts` are host names or `*.domain` patterns; requests and redirects must stay on https and on
  these hosts. On a redirect to a host other than the one the request started on, the auth header
  is removed before the redirect is followed (e.g. GitHub job logs: `api.github.com` →
  `*.blob.core.windows.net`, so add both to `hosts`). Redirect URLs may be up to 2047 bytes.
- `GET`/`HEAD` run directly; other methods ask for confirmation in Telegram. `read_only_posts`
  (optional) lists `POST` endpoints that only read and run without confirmation: `/path`
  patterns are matched against the path after `base_url`, `https://host/path` patterns against
  the whole URL; the query string is ignored and `*` matches any characters except `/`. Example:
  `["/v1/projects/*/analytics/endpoints/logs*"]`.
