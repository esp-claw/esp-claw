/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>

#include "claw_cap.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t cap_http_request_register_group(void);
esp_err_t cap_http_request_set_allowlist(const char *allowlist_csv);
/* Sets the credential profiles (JSON array, see api_profiles); the string holds secrets. */
esp_err_t cap_http_request_set_profiles(const char *profiles_json);
/*
 * Runs one request through credential profile `profile` with the same host checks, auth injection
 * and Telegram confirmation of mutations as http_request with "profile"; `ctx` must be the
 * originating tool call's context. `path_or_url` is a "/path" appended to the profile's base_url
 * or a full https URL on the profile's hosts; `headers_json` is a JSON object of strings or NULL.
 * On ESP_OK `*out_status` is the HTTP status and `output` the response body (at most `max_body`
 * bytes); otherwise `output` holds an error message.
 */
esp_err_t cap_http_request_profile_call(const char *profile, const char *method, const char *path_or_url,
                                        const char *headers_json, const char *body, size_t max_body,
                                        const claw_cap_call_context_t *ctx,
                                        int *out_status, char *output, size_t output_size);

#ifdef __cplusplus
}
#endif
