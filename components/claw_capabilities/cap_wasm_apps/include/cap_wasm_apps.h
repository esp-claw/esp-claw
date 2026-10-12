/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Set the Ed25519 keys apps must be signed with and whether apps without a valid
 *         signature may load anyway. Call before cap_wasm_apps_register_group().
 *
 * @param trusted_keys_json  JSON array (app_trusted_keys) of base64 raw 32-byte public keys, or
 *                           {"key":"<base64>","apps":["<name prefix>",...]} for a key trusted only
 *                           for apps with those name prefixes (not for firmware); invalid entries
 *                           are skipped with a warning
 * @param allow_unsigned     app_allow_unsigned
 */
void cap_wasm_apps_set_trust(const char *trusted_keys_json, bool allow_unsigned);

/**
 * @brief  Set the local time ("HH:MM", update_check_time) of the daily check for firmware and app
 *         updates, which tells the allowed Telegram users about new ones; it also runs once per
 *         boot and on cap_wasm_updates_kick(). "" or an invalid value turns all of them off. Call
 *         before cap_wasm_apps_register_group().
 */
void cap_wasm_apps_set_update_check(const char *hhmm);

/**
 * @brief  Start the update check in the background (e.g. when a chat session starts), unless
 *         checks are off, one is running or one ran within the last hour. Does not block.
 */
void cap_wasm_updates_kick(void);

/**
 * @brief  Start the WASM app runtime and register the tools of every enabled, validly signed
 *         app in <base_path>/apps/<name>/ in the "cap_wasm_apps" group (apps load on their first
 *         call), plus the management tools and the /apps and /app command handler in
 *         "cap_wasm_apps_mgr". App errors are logged and never fail boot.
 *
 *         The same group holds the firmware update tools (firmware_status/check/update and the
 *         /fw handler, signed by the same trusted keys), and this call starts the post-update
 *         health check that confirms a freshly booted image or lets the bootloader roll back.
 */
esp_err_t cap_wasm_apps_register_group(const char *base_path);

/*
 * Management for a trusted local user channel (the authenticated web UI). Each call writes a
 * result to `out`: JSON on success for the *_json calls, otherwise a human-readable message
 * (also the error text on failure). They block until the WASM thread has handled the request.
 */

/**
 * @brief  JSON array of the installed apps (name, version, state, enabled, tools, last_error, timer, ...).
 *         ESP_ERR_INVALID_STATE when the WASM app runtime is not running.
 */
esp_err_t cap_wasm_apps_status_json(char *out, size_t size);

/**
 * @brief  JSON {app, settings:[{key, type, description, secret, set, value?, default?}]} of app
 *         `name`; secret values are never included.
 */
esp_err_t cap_wasm_apps_settings_json(const char *name, char *out, size_t size);

/**
 * @brief  Enables (loads and registers its tools) or disables app `name`; persists across reboots.
 */
esp_err_t cap_wasm_apps_set_enabled(const char *name, bool enabled, char *out, size_t size);

/**
 * @brief  Sets setting `key` of app `name` to `value`, or resets it to its default when `value`
 *         is NULL. The value is validated against the setting type declared in the manifest.
 */
esp_err_t cap_wasm_apps_set_setting(const char *name, const char *key, const char *value, char *out, size_t size);

#ifdef __cplusplus
}
#endif
