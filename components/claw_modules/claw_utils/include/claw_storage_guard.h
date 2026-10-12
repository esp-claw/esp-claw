/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stddef.h>
#include <stdio.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Space kept available for recovery, cleanup, and essential internal writes. */
#define CLAW_STORAGE_RESERVE_BYTES (128U * 1024U)

/* Used until the mounted DATA volume reports its actual allocation unit. */
#define CLAW_STORAGE_DEFAULT_ALLOCATION_UNIT_BYTES (64U * 1024U)

/** Configure the allocation unit used to round prospective writes. Zero restores the fallback. */
void claw_storage_set_allocation_unit(size_t allocation_unit);

/** Return the configured allocation unit, or the conservative fallback when it is not known. */
size_t claw_storage_get_allocation_unit(void);

/**
 * Check whether a nonessential write fits without consuming the recovery reserve.
 *
 * incoming_bytes is rounded up to the current allocation unit and one additional unit is allowed for
 * directory/FAT metadata. Callers must run this before opening or truncating the destination. Essential
 * internal recovery writes intentionally bypass this guard.
 */
esp_err_t claw_storage_check_write(const char *root_path, size_t incoming_bytes);

/**
 * Acquire the shared write lock and check the reserve. A successful call must
 * be paired with claw_storage_end_write() after allocation, flush, and close.
 * Do not nest begin/end pairs.
 */
esp_err_t claw_storage_begin_write(const char *root_path, size_t incoming_bytes);

/** Release a successful claw_storage_begin_write() call. */
void claw_storage_end_write(void);

/**
 * Acquire the shared write lock, check the reserve, and open a replacement.
 * The lock remains held on success and must be released with
 * claw_storage_end_write() after flush and close. A failure releases it.
 */
esp_err_t claw_storage_open_write(const char *root_path,
                                  const char *file_path,
                                  size_t incoming_bytes,
                                  FILE **out_file);

#ifdef __cplusplus
}
#endif
