/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Update lookups in GitHub releases. Pure C so it can be unit-tested on the host. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cap_wasm_manifest.h"

#define CAP_WASM_GH_REPO_MAX  96   /* "<owner>/<repo>" incl. NUL */
#define CAP_WASM_REL_URL_MAX  256
#define CAP_WASM_REL_SCAN_MAX (64 * 1024) /* assets come early in releases/latest; the rest is ignored */
#define CAP_WASM_NOTIFY_AGAIN_S (7 * 24 * 3600)

/* "<owner>/<repo>" of https://github.com/<owner>/<repo>/releases/download/<tag>/<file>; false for other URLs. */
bool cap_wasm_gh_release_repo(const char *url, char *repo, size_t repo_size);

/* App name and version of an asset file named "<name>-<version>.ecapp"; false for other names. */
bool cap_wasm_ecapp_name_version(const char *file, char name[CAP_WASM_APP_NAME_MAX + 1],
                                 char version[CAP_WASM_VERSION_MAX + 1]);

typedef void (*cap_wasm_rel_asset_fn)(void *ctx, const char *url);

/*
 * Streaming scanner over a releases/latest JSON body: keeps "tag_name" and hands every
 * "browser_download_url" to on_asset, without building a JSON tree. Zero-initialise, set on_asset
 * and ctx, then feed the body in chunks of any size.
 */
typedef struct {
    cap_wasm_rel_asset_fn on_asset;
    void *ctx;
    char tag[CAP_WASM_VERSION_MAX + 2];
    char str[CAP_WASM_REL_URL_MAX]; /* string being read */
    size_t str_len;
    size_t seen;
    uint8_t state;
    uint8_t key;
    bool in_str;
    bool esc;
    bool overflow;
    bool done;
} cap_wasm_rel_scan_t;

void cap_wasm_rel_scan_feed(cap_wasm_rel_scan_t *s, const char *data, size_t len);

/* Picks the package of app `name` from the asset URLs: "<name>-<version>.ecapp", else the only .ecapp. */
typedef struct {
    const char *name;
    char url[CAP_WASM_REL_URL_MAX];
    char version[CAP_WASM_VERSION_MAX + 1];
    int ecapps;
    bool exact;
} cap_wasm_rel_app_t;

void cap_wasm_rel_app_asset(void *ctx, const char *url);

/* True when a package was found; its version falls back to the release tag without a leading 'v'. */
bool cap_wasm_rel_app_pick(cap_wasm_rel_app_t *a, const char *tag);

/*
 * Whether to announce `cur` ("name=version;..."): when it is not empty and lists an entry that
 * `last` (announced at `last_at`) does not, or CAP_WASM_NOTIFY_AGAIN_S have passed since.
 */
bool cap_wasm_should_notify(const char *last, int64_t last_at, const char *cur, int64_t now);
