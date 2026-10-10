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

esp_err_t cap_ssh_register_group(void);
/* JSON array of {"name","host","port","user","fingerprint","workdir"}; "workdir" is optional and
 * enables the remote_* file tools for that host. Call before registering the group. */
esp_err_t cap_ssh_set_hosts(const char *hosts_json);

#ifdef __cplusplus
}
#endif
