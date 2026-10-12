# About this fork

This repository, [esp-claw/esp-claw](https://github.com/esp-claw/esp-claw), is an unofficial community fork of [espressif/esp-claw](https://github.com/espressif/esp-claw). It is not affiliated with or endorsed by Espressif. Upstream code keeps its original copyright headers; issues in code this fork does not change belong upstream.

## What the fork adds

- **Telegram**: sender allowlist (`tg_allowed_user_ids`), replies as rich messages with a "thinking" bubble, voice and audio transcription through an OpenAI-compatible speech-to-text endpoint, album photos and captions passed to the agent, one command table for `/help` and the bot menu.
- **Confirmations**: actions with side effects ask for a button press in the Telegram chat the request came from, including requests handled by subagents.
- **SSH**: `ssh_exec` with pinned host keys, per-command confirmation and user-defined allow rules; `remote_*` file tools over SFTP inside a per-host working directory.
- **Wake-on-LAN**: `wol_wake` for configured targets.
- **Credential profiles**: API tokens stay on the device; requests are pinned to the profile's hosts over https, auth is dropped on cross-host redirects, and only `GET`/`HEAD` and listed `read_only_posts` run without confirmation.
- **Memory v2**: session-level extraction, reconcile and consolidation, scored recall with an optional embeddings endpoint, and repair of tool call/output pairing before every LLM request.
- **WebDAV** at `/dav` with quota properties.
- **WASM apps**: a WAMR-based app runtime with signed `.ecapp` packages (Ed25519), permissions in the manifest, an installer with rollback, and update checks. The SDK and apps live in [esp-claw/app-sdk](https://github.com/esp-claw/app-sdk) and the `app-*` repositories. See "App package model" below.
- **Signed OTA firmware updates** with automatic rollback if the new image does not come up (`/fw`), plus daily update checks for firmware and apps (`/updates`). Nothing is installed without a confirmation.
- **Web UI over HTTPS** (port 443, self-signed certificate, LAN only) with login through a one-time link from Telegram (`/web`).
- An `openai_codex` LLM backend with ChatGPT device login, a file-area quota, and a slimmer DevKitC-1 build (no display, BLE or QQ/Feishu/WeChat).

`git log --oneline <merge-base>..master`, where the merge base is `git merge-base master upstream/master`, lists every change.

## App package model

`components/claw_capabilities/cap_wasm_apps` (host-testable parts in `cap_wasm_pkg.[ch]` and `cap_wasm_manifest.[ch]`, `test/host/run.sh`) implements package format 2. Format 1 packages are still accepted; `ecapp.py pack --format 1` still writes them. What changed and why:

- **Signatures over bytes, not canonical JSON.** Format 1 signed the canonical JSON of a `signed` object that repeated the app name, version and the hex entry hashes; both sides had to produce that text byte for byte, and every future field would have changed the canonical form. Format 2 keeps `signature.json` as `{"alg","key_id","sdk":2,"sig"}` and signs a fixed binary record built from the manifest and the entry bytes: `"ecapp-sig-v2"` + NUL, u8 format 2, u16 LE `api`, u8-length-prefixed name and version, SHA-256 of `manifest.json`, SHA-256 of `app.wasm` (byte-exact layout in `cap_wasm_pkg.h`). The package format byte and `sdk` must agree.
- **Host API version.** The manifest's `api` (required in format 2, read as 1 when absent from a format 1 manifest) is the `claw` import module version the app was built for and is part of the signed record. The firmware implements api 2 (`CAP_WASM_API_VERSION`; 2 added `time_utc`, which writes u64 LE unix milliseconds and a quality byte: none, synced, authenticated). It refuses an app that needs a newer api ("needs claw api N, firmware has M") and one that imports a function newer than its declared api; the import permission check stays.
- **Anti-rollback.** Every successful install records the version as the app's floor in NVS (`_floor` next to the timer state; it outlives `/app remove`). Installing a lower version, or one that cannot be compared, is refused with the floor in the message unless the user passes `--allow-downgrade` (`--force` still works); such an install is always confirmed with a button that says "Downgrade", and then the floor follows the installed version. Before, `/app remove` followed by an install of an old signed package with a known bug went through silently.
- **Signed update index with expiry.** Update checks no longer trust the GitHub releases API: that answer was unsigned, so whoever controlled the path could hide new releases forever (a freeze attack) or offer a different package. Each app source publishes `index.json` and `index.sig`, the latter an Ed25519 signature over `"ecapp-index-v1"` + NUL, SHA-256 of the `index.json` bytes and u64 LE `expires`; the `expires` inside `index.json` must match. The device fetches them from `releases/latest/download/` of a GitHub release source (else from the package's directory), refuses an expired index or one issued before the last index it accepted for that app (NVS `_issued`), reports "clock not synced, cannot verify index freshness" and installs nothing without a synced clock, and checks the downloaded package against the entry's size, SHA-256 and version. `ecapp.py index` writes and signs the two files. The firmware check keeps using the release API; the image signature binds project and version, and the daily check never installs anything.
- **Scoped keys.** An `app_trusted_keys` entry may be `{"key":"<base64>","apps":["<prefix>",...]}`: trusted only for apps whose name starts with one of the prefixes, never for firmware or other apps' index entries. Plain entries are unchanged.
- **Shared test vectors.** `test/host/ecapp_vectors.json` (the SDK's `tests/ecapp_vectors.json`, generated by its `tests/make_vectors.py`) holds the test key, the format 2 record, a format 1 signature and a signed index with their signatures. The firmware's host tests, the SDK self-test and rust-claw (the Rust port of this runtime) check the same bytes.

## Supported board

Only **ESP32-S3-DevKitC-1 N8R8** (8 MB flash, 8 MB PSRAM) is built and tested, as board `esp32_S3_DevKitC_1` with `application/edge_agent/partitions_8MB_ota.csv` (two 3200K app slots). Other upstream boards may still build, but this fork does not test them.

Build:

```bash
cd application/edge_agent
. "$IDF_PATH/export.sh"          # ESP-IDF v5.5.4
pip install esp-bmgr-assist
idf.py bmgr -c ./boards -b esp32_S3_DevKitC_1
idf.py build
```

A board flashed with the older layout can move to the OTA layout without losing NVS or `/fatfs`: `tools/migrate_ota_layout.sh -p <port>`.

## Releases

1. A maintainer pushes a tag `vMAJOR.MINOR.PATCH`.
2. `.github/workflows/firmware_release.yml` builds `edge_agent.bin` with that version and attaches the unsigned image to the GitHub release.
3. The maintainer downloads it, checks its SHA-256 against the CI log, signs it locally with `tools/fwsign.py sign edge_agent.bin --key <ed25519.pem>` and uploads `edge_agent.bin.sig.json` to the same release. CI never sees the private key.
4. Devices find the new version with `/fw check` (or the daily update check) and install it with `/fw update`. They accept only images signed by a key in `app_trusted_keys`.

`.github/workflows/firmware_ci.yml` runs the host tests and a full build on every push and pull request to `master`.

## Staying in sync with upstream

```bash
git remote add upstream https://github.com/espressif/esp-claw.git
git fetch upstream
git switch master
git merge upstream/master        # resolve conflicts, build, run the host tests
```

Merge rather than rebase, so that published commits keep their hashes.

## Licensing

The project is Apache-2.0 (see [LICENSE](LICENSE)), like upstream. The SSH tool statically links [libssh](https://www.libssh.org/), which is LGPL-2.1. Check its terms before you distribute firmware binaries; the LGPL's relinking requirements apply to statically linked builds.
