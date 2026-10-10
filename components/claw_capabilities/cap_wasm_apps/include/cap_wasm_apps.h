/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief  Start the WASM app runtime, load every app in <base_path>/apps/<name>/
 *         (manifest.json + app.wasm) and register their tools in the "cap_wasm_apps"
 *         group, plus the apps_status tool and the /apps command handler. App errors
 *         are logged and never fail boot.
 */
esp_err_t cap_wasm_apps_register_group(const char *base_path);

#ifdef __cplusplus
}
#endif
