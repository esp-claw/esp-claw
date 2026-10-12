/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_storage_guard.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#include "esp_vfs_fat.h"

static _Atomic size_t s_allocation_unit;
static pthread_once_t s_write_lock_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t s_write_lock;
static int s_write_lock_init_result;

static void claw_storage_init_write_lock(void)
{
    s_write_lock_init_result = pthread_mutex_init(&s_write_lock, NULL);
}

void claw_storage_set_allocation_unit(size_t allocation_unit)
{
    atomic_store(&s_allocation_unit, allocation_unit);
}

size_t claw_storage_get_allocation_unit(void)
{
    size_t allocation_unit = atomic_load(&s_allocation_unit);

    return allocation_unit > 0 ? allocation_unit : CLAW_STORAGE_DEFAULT_ALLOCATION_UNIT_BYTES;
}

esp_err_t claw_storage_check_write(const char *root_path, size_t incoming_bytes)
{
    uint64_t total_bytes = 0;
    uint64_t free_bytes = 0;
    size_t allocation_unit;
    uint64_t allocated_bytes = 0;
    uint64_t required_bytes;
    esp_err_t err;

    if (!root_path || !root_path[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    allocation_unit = claw_storage_get_allocation_unit();
#if SIZE_MAX == UINT64_MAX
    if ((uint64_t)allocation_unit > UINT64_MAX - CLAW_STORAGE_RESERVE_BYTES) {
        return ESP_ERR_INVALID_SIZE;
    }
#endif
    if (incoming_bytes > 0) {
        uint64_t incoming = incoming_bytes;
        uint64_t unit = allocation_unit;

        if (incoming > UINT64_MAX - (unit - 1)) {
            return ESP_ERR_INVALID_SIZE;
        }
        allocated_bytes = ((incoming + unit - 1) / unit) * unit;
    }
    if (allocated_bytes > UINT64_MAX - CLAW_STORAGE_RESERVE_BYTES - allocation_unit) {
        return ESP_ERR_INVALID_SIZE;
    }
    required_bytes = allocated_bytes + allocation_unit + CLAW_STORAGE_RESERVE_BYTES;

    err = esp_vfs_fat_info(root_path, &total_bytes, &free_bytes);
    if (err != ESP_OK) {
        return err;
    }

    return free_bytes >= required_bytes ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t claw_storage_begin_write(const char *root_path, size_t incoming_bytes)
{
    esp_err_t err;

    if (pthread_once(&s_write_lock_once, claw_storage_init_write_lock) != 0 || s_write_lock_init_result != 0) {
        return ESP_FAIL;
    }
    if (pthread_mutex_lock(&s_write_lock) != 0) {
        return ESP_FAIL;
    }

    err = claw_storage_check_write(root_path, incoming_bytes);
    if (err != ESP_OK) {
        pthread_mutex_unlock(&s_write_lock);
    }
    return err;
}

void claw_storage_end_write(void)
{
    pthread_mutex_unlock(&s_write_lock);
}

esp_err_t claw_storage_open_write(const char *root_path,
                                  const char *file_path,
                                  size_t incoming_bytes,
                                  FILE **out_file)
{
    esp_err_t err;

    if (!file_path || !file_path[0] || !out_file) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_file = NULL;

    err = claw_storage_begin_write(root_path, incoming_bytes);
    if (err != ESP_OK) {
        return err;
    }

    *out_file = fopen(file_path, "wb");
    if (!*out_file) {
        claw_storage_end_write();
        return ESP_FAIL;
    }
    return ESP_OK;
}
