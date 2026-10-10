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

esp_err_t cap_wol_register_group(void);
/* JSON array of {"name","mac","broadcast","port"}; call before registering the group. */
esp_err_t cap_wol_set_targets(const char *targets_json);

#ifdef __cplusplus
}
#endif
