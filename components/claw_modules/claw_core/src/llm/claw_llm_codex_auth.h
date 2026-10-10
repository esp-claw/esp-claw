/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef struct {
    char *user_code;
    char *device_auth_id;
    int interval_s;
} claw_llm_codex_device_t;

esp_err_t claw_llm_codex_auth_init(void);
esp_err_t claw_llm_codex_device_start(claw_llm_codex_device_t *out_device, char **out_error_message);
esp_err_t claw_llm_codex_device_wait(const claw_llm_codex_device_t *device, char **out_error_message);
void claw_llm_codex_device_free(claw_llm_codex_device_t *device);
esp_err_t claw_llm_codex_get_access_token(bool force_refresh,
                                          char **out_access_token,
                                          char **out_account_id,
                                          char **out_error_message);
bool claw_llm_codex_is_logged_in(int64_t *out_expires_at);
esp_err_t claw_llm_codex_logout(void);
