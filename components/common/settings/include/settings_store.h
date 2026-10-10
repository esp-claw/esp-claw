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

typedef struct {
    const char *namespace_name;
} settings_store_config_t;

esp_err_t settings_store_init(const settings_store_config_t *config);
esp_err_t settings_store_get_string(const char *key,
                                    char *buf,
                                    size_t buf_size,
                                    const char *default_value);
esp_err_t settings_store_has_key(const char *key, bool *exists);
esp_err_t settings_store_set_string(const char *key, const char *value);
esp_err_t settings_store_erase_key(const char *key);
/* Blobs may span NVS pages (strings must fit in one). `*len`: buffer size in, bytes read out;
 * ESP_ERR_NVS_NOT_FOUND when the key does not exist. */
esp_err_t settings_store_get_blob(const char *key, void *buf, size_t *len);
esp_err_t settings_store_set_blob(const char *key, const void *data, size_t len);
esp_err_t settings_store_commit(void);

#ifdef __cplusplus
}
#endif
