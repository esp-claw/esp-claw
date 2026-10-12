/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

#include "claw_storage_guard.h"

static uint64_t s_total_bytes = 4U * 1024U * 1024U;
static uint64_t s_free_bytes;
static esp_err_t s_info_result = ESP_OK;
static pthread_mutex_t s_test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_test_cond = PTHREAD_COND_INITIALIZER;
static bool s_first_began;
static bool s_release_first;
static bool s_second_attempted;
static _Atomic bool s_second_done;
static esp_err_t s_second_result;

esp_err_t esp_vfs_fat_info(const char *base_path, uint64_t *out_total_bytes, uint64_t *out_free_bytes)
{
    assert(strcmp(base_path, "/data") == 0);
    *out_total_bytes = s_total_bytes;
    *out_free_bytes = s_free_bytes;
    return s_info_result;
}

static void test_exact_boundary_and_rounding(void)
{
    const size_t unit = 4096;

    claw_storage_set_allocation_unit(unit);
    assert(claw_storage_get_allocation_unit() == unit);

    /* One byte occupies one unit, plus one unit for FAT/directory metadata. */
    s_free_bytes = CLAW_STORAGE_RESERVE_BYTES + 2 * unit;
    assert(claw_storage_check_write("/data", 1) == ESP_OK);
    s_free_bytes--;
    assert(claw_storage_check_write("/data", 1) == ESP_ERR_NO_MEM);

    /* Exact multiples are not rounded to an extra data unit. */
    s_free_bytes = CLAW_STORAGE_RESERVE_BYTES + 2 * unit;
    assert(claw_storage_check_write("/data", unit) == ESP_OK);
}

static void test_full_disk_and_query_errors(void)
{
    s_free_bytes = 0;
    assert(claw_storage_check_write("/data", 0) == ESP_ERR_NO_MEM);
    assert(claw_storage_check_write(NULL, 1) == ESP_ERR_INVALID_ARG);

    s_info_result = ESP_FAIL;
    assert(claw_storage_check_write("/data", 1) == ESP_FAIL);
    s_info_result = ESP_OK;

    claw_storage_set_allocation_unit(0);
    assert(claw_storage_get_allocation_unit() == CLAW_STORAGE_DEFAULT_ALLOCATION_UNIT_BYTES);

    claw_storage_set_allocation_unit(SIZE_MAX);
    assert(claw_storage_check_write("/data", 1) == ESP_ERR_INVALID_SIZE);
}

static void test_refusal_does_not_truncate_existing_file(void)
{
    char path[] = "/tmp/claw-storage-guard-XXXXXX";
    const char original[] = "keep this data";
    char actual[sizeof(original)] = {0};
    FILE *file = NULL;
    int fd = mkstemp(path);

    assert(fd >= 0);
    assert(write(fd, original, sizeof(original)) == (ssize_t)sizeof(original));
    assert(close(fd) == 0);

    claw_storage_set_allocation_unit(4096);
    s_free_bytes = CLAW_STORAGE_RESERVE_BYTES + 2 * 4096 - 1;
    assert(claw_storage_open_write("/data", path, 1, &file) == ESP_ERR_NO_MEM);
    assert(file == NULL);

    file = fopen(path, "rb");
    assert(file != NULL);
    assert(fread(actual, 1, sizeof(actual), file) == sizeof(actual));
    assert(fclose(file) == 0);
    assert(memcmp(actual, original, sizeof(original)) == 0);
    assert(unlink(path) == 0);
}

static void *concurrent_first_writer(void *arg)
{
    const size_t unit = *(const size_t *)arg;

    assert(claw_storage_begin_write("/data", 1) == ESP_OK);
    pthread_mutex_lock(&s_test_lock);
    s_first_began = true;
    pthread_cond_broadcast(&s_test_cond);
    while (!s_release_first) {
        pthread_cond_wait(&s_test_cond, &s_test_lock);
    }
    pthread_mutex_unlock(&s_test_lock);

    /* Simulate the first write becoming visible before its lock is released. */
    s_free_bytes = CLAW_STORAGE_RESERVE_BYTES + 2 * unit - 1;
    claw_storage_end_write();
    return NULL;
}

static void *concurrent_second_writer(void *arg)
{
    (void)arg;

    pthread_mutex_lock(&s_test_lock);
    s_second_attempted = true;
    pthread_cond_broadcast(&s_test_cond);
    pthread_mutex_unlock(&s_test_lock);

    s_second_result = claw_storage_begin_write("/data", 1);
    if (s_second_result == ESP_OK) {
        claw_storage_end_write();
    }
    atomic_store(&s_second_done, true);
    return NULL;
}

static void test_concurrent_writers_are_serialized(void)
{
    const size_t unit = 4096;
    pthread_t first;
    pthread_t second;

    claw_storage_set_allocation_unit(unit);
    s_free_bytes = CLAW_STORAGE_RESERVE_BYTES + 2 * unit;
    s_first_began = false;
    s_release_first = false;
    s_second_attempted = false;
    atomic_store(&s_second_done, false);

    assert(pthread_create(&first, NULL, concurrent_first_writer, (void *)&unit) == 0);
    pthread_mutex_lock(&s_test_lock);
    while (!s_first_began) {
        pthread_cond_wait(&s_test_cond, &s_test_lock);
    }
    pthread_mutex_unlock(&s_test_lock);

    assert(pthread_create(&second, NULL, concurrent_second_writer, NULL) == 0);
    pthread_mutex_lock(&s_test_lock);
    while (!s_second_attempted) {
        pthread_cond_wait(&s_test_cond, &s_test_lock);
    }
    pthread_mutex_unlock(&s_test_lock);

    usleep(20000);
    assert(!atomic_load(&s_second_done));

    pthread_mutex_lock(&s_test_lock);
    s_release_first = true;
    pthread_cond_broadcast(&s_test_cond);
    pthread_mutex_unlock(&s_test_lock);

    assert(pthread_join(first, NULL) == 0);
    assert(pthread_join(second, NULL) == 0);
    assert(s_second_result == ESP_ERR_NO_MEM);
}

int main(void)
{
    test_exact_boundary_and_rounding();
    test_full_disk_and_query_errors();
    test_refusal_does_not_truncate_existing_file();
    test_concurrent_writers_are_serialized();
    puts("claw_storage_guard host tests passed");
    return 0;
}
