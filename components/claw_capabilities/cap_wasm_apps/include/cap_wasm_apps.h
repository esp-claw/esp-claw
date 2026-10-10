/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Set the Ed25519 keys apps must be signed with and whether apps without a valid
 *         signature may load anyway. Call before cap_wasm_apps_register_group().
 *
 * @param trusted_keys_json  JSON array of base64 raw 32-byte public keys (app_trusted_keys);
 *                           invalid entries are skipped with a warning
 * @param allow_unsigned     app_allow_unsigned
 */
void cap_wasm_apps_set_trust(const char *trusted_keys_json, bool allow_unsigned);

/**
 * @brief  Start the WASM app runtime and register the tools of every enabled, validly signed
 *         app in <base_path>/apps/<name>/ in the "cap_wasm_apps" group (apps load on their first
 *         call), plus the management tools and the /apps and /app command handler in
 *         "cap_wasm_apps_mgr". App errors are logged and never fail boot.
 */
esp_err_t cap_wasm_apps_register_group(const char *base_path);

#ifdef __cplusplus
}
#endif
