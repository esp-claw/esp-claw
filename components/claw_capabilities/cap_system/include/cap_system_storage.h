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

/**
 * Set the allocation unit reported by /storage.
 *
 * The mount layer should call this once DATA is mounted with the actual FAT
 * cluster size. Pass zero when the geometry is unknown. The value is also
 * forwarded to the shared write-reserve guard.
 */
void cap_system_storage_set_allocation_unit(size_t bytes);

/** Initialize command state before registering the descriptor. Idempotent. */
esp_err_t cap_system_storage_init(void);

/** Execute the restricted, non-LLM /storage command capability. */
esp_err_t cap_system_storage_execute(const char *input_json,
                                     const claw_cap_call_context_t *ctx,
                                     char *output,
                                     size_t output_size);

/** Start the bounded low-space monitor. Safe to call more than once. */
esp_err_t cap_system_storage_start_monitor(void);

#ifdef __cplusplus
}
#endif
