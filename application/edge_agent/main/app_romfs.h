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
 * @brief  Serve the system files embedded in the app image (skills, built-in Lua scripts and
 *         the recovery seeds) read-only at `base_path`.
 *
 *         Only available with CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED.
 *
 * @return
 *       - ESP_OK                 On success
 *       - ESP_ERR_INVALID_STATE  The embedded image is malformed
 *       - Others                 VFS registration error
 */
esp_err_t app_romfs_register(const char *base_path);

#ifdef __cplusplus
}
#endif
