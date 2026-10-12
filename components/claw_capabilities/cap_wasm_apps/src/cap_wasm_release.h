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

/*
 * Whether to announce `cur` ("name=version;..."): when it is not empty and lists an entry that
 * `last` (announced at `last_at`) does not, or CAP_WASM_NOTIFY_AGAIN_S have passed since.
 */
bool cap_wasm_should_notify(const char *last, int64_t last_at, const char *cur, int64_t now);
