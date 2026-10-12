/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_system_storage.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "claw_memory.h"
#include "claw_paths.h"
#include "claw_storage_guard.h"
#include "esp_vfs_fat.h"

#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
#include <pthread.h>
#else
#include "claw_task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#endif

#define STORAGE_PATH_MAX              256
#define STORAGE_SCAN_MAX_ENTRIES      512
#define STORAGE_CANDIDATE_MAX         12
#define STORAGE_SCAN_MAX_DEPTH        3
#define STORAGE_SAFE_MIN_AGE_SEC      (24U * 60U * 60U)
#define STORAGE_ATTACHMENT_MIN_AGE_SEC (7U * 24U * 60U * 60U)
#define STORAGE_TOKEN_TTL_SEC         (5U * 60U)
#define STORAGE_MONITOR_PERIOD_MS     (15U * 60U * 1000U)
#define STORAGE_MONITOR_INITIAL_MS    (30U * 1000U)
#define STORAGE_VALID_EPOCH           1704067200

#ifndef CAP_SYSTEM_STORAGE_HOST_TEST
static const char *TAG = "cap_system_storage";
#endif

#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
extern int cap_system_storage_test_lstat(const char *path, struct stat *st);
extern struct dirent *cap_system_storage_test_readdir(DIR *dir);
extern int cap_system_storage_test_closedir(DIR *dir);
#define storage_lstat(path, st) cap_system_storage_test_lstat((path), (st))
#define storage_readdir(dir) cap_system_storage_test_readdir((dir))
#define storage_closedir(dir) cap_system_storage_test_closedir((dir))
#else
/* ESP-IDF's FAT VFS has no symlinks and does not expose lstat(). */
#define storage_lstat(path, st) stat((path), (st))
#define storage_readdir(dir) readdir((dir))
#define storage_closedir(dir) closedir((dir))
#endif

typedef enum {
    STORAGE_CANDIDATE_SIDECAR,
    STORAGE_CANDIDATE_TEMP,
    STORAGE_CANDIDATE_ATTACHMENT,
} storage_candidate_kind_t;

typedef enum {
    STORAGE_PENDING_NONE,
    STORAGE_PENDING_FILES,
    STORAGE_PENDING_REPAIR,
} storage_pending_kind_t;

typedef struct {
    char relative_path[STORAGE_PATH_MAX];
    off_t size;
    time_t mtime;
    storage_candidate_kind_t kind;
} storage_candidate_t;

typedef struct {
    storage_candidate_t *items;
    size_t count;
    size_t eligible_count;
    size_t scanned;
    bool truncated;
    bool scan_error;
} storage_candidate_set_t;

typedef struct {
    uint64_t logical;
    uint64_t allocated;
    size_t files;
    bool truncated;
} storage_usage_t;

typedef struct {
    storage_pending_kind_t kind;
    storage_candidate_t *items;
    size_t count;
    char token[17];
    char channel[16];
    char chat_id[64];
    uint64_t expires_at_ms;
} storage_pending_t;

typedef struct {
    char paths[STORAGE_SCAN_MAX_DEPTH + 2][STORAGE_PATH_MAX];
    struct stat stat_buf[STORAGE_SCAN_MAX_DEPTH + 2];
} storage_usage_scan_t;

typedef struct {
    char sessions[STORAGE_PATH_MAX];
    char path[STORAGE_PATH_MAX];
    char base[STORAGE_PATH_MAX];
    char log_path[STORAGE_PATH_MAX];
    char idx_path[STORAGE_PATH_MAX];
    char relative[STORAGE_PATH_MAX];
    struct stat stat_buf;
    struct stat lookup_stat;
} storage_sidecar_scan_t;

typedef struct {
    char relative[STORAGE_SCAN_MAX_DEPTH + 2][STORAGE_PATH_MAX];
    char full_path[STORAGE_PATH_MAX];
    struct stat stat_buf[STORAGE_SCAN_MAX_DEPTH + 2];
} storage_inbox_scan_t;

typedef struct {
    char sibling[STORAGE_PATH_MAX];
    struct stat stat_buf;
} storage_revalidate_t;

#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
typedef struct {
    size_t reported_allocation_unit;
    storage_pending_t pending;
    uint32_t token_counter;
    pthread_mutex_t mutex;
} storage_state_t;

static storage_state_t s_storage = {.mutex = PTHREAD_MUTEX_INITIALIZER};

static bool storage_lock(void)
{
    return pthread_mutex_lock(&s_storage.mutex) == 0;
}

static void storage_unlock(void)
{
    pthread_mutex_unlock(&s_storage.mutex);
}
#else
typedef struct {
    size_t reported_allocation_unit;
    storage_pending_t pending;
    uint32_t token_counter;
    SemaphoreHandle_t mutex;
    bool monitor_started;
} storage_state_t;

static storage_state_t s_storage;

static bool storage_lock(void)
{
    return s_storage.mutex && xSemaphoreTake(s_storage.mutex, portMAX_DELAY) == pdTRUE;
}

static void storage_unlock(void)
{
    xSemaphoreGive(s_storage.mutex);
}
#endif

static void storage_write(char *output, size_t output_size, const char *fmt, ...)
{
    va_list args;

    if (!output || output_size == 0) {
        return;
    }
    va_start(args, fmt);
    vsnprintf(output, output_size, fmt, args);
    va_end(args);
}

static void storage_append(char *output, size_t output_size, size_t *offset, const char *fmt, ...)
{
    va_list args;
    int written;

    if (!output || !offset || *offset >= output_size) {
        return;
    }
    va_start(args, fmt);
    written = vsnprintf(output + *offset, output_size - *offset, fmt, args);
    va_end(args);
    if (written > 0) {
        *offset += (size_t)written < output_size - *offset ? (size_t)written : output_size - *offset - 1;
    }
}

static bool storage_has_suffix(const char *value, const char *suffix)
{
    size_t value_len = value ? strlen(value) : 0;
    size_t suffix_len = suffix ? strlen(suffix) : 0;

    return suffix_len <= value_len && strcmp(value + value_len - suffix_len, suffix) == 0;
}

static bool storage_join_child(char *out, size_t out_size, const char *parent, const char *name)
{
    size_t parent_len = strlen(parent);
    size_t name_len = strlen(name);

    if (out == parent || parent_len + 1 + name_len + 1 > out_size) {
        return false;
    }
    memcpy(out, parent, parent_len);
    out[parent_len] = '/';
    memcpy(out + parent_len + 1, name, name_len + 1);
    return true;
}

static struct dirent *storage_read_dir(DIR *dir, bool *read_error)
{
    struct dirent *entry;

    errno = 0;
    entry = storage_readdir(dir);
    if (!entry && errno != 0 && read_error) {
        *read_error = true;
    }
    return entry;
}

static bool storage_close_dir(DIR *dir)
{
    errno = 0;
    return storage_closedir(dir) == 0;
}

static bool storage_old_enough(time_t mtime, uint32_t minimum_age)
{
    time_t now = time(NULL);

    return now >= STORAGE_VALID_EPOCH && mtime > 0 && mtime <= now &&
           (uint64_t)(now - mtime) >= minimum_age;
}

static bool storage_path_absent(const char *path, bool *lookup_error, struct stat *stat_buf)
{
    if (storage_lstat(path, stat_buf) == 0) {
        return false;
    }
    if (errno == ENOENT) {
        return true;
    }
    if (lookup_error) {
        *lookup_error = true;
    }
    return false;
}

static uint64_t storage_allocated_size(off_t size)
{
    size_t unit = s_storage.reported_allocation_unit;

    if (size <= 0 || unit == 0) {
        return 0;
    }
    return ((uint64_t)size + unit - 1) / unit * unit;
}

static bool storage_known_top_level(const char *name)
{
    static const char *const known[] = {"sessions", "inbox", "memory", "skills", "apps"};

    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (strcmp(name, known[i]) == 0) {
            return true;
        }
    }
    return false;
}

static void storage_scan_usage_path(unsigned depth, size_t *scanned, storage_usage_t *usage,
                                    storage_usage_scan_t *scratch)
{
    const char *path = scratch->paths[depth];
    struct stat *st = &scratch->stat_buf[depth];

    if (usage->truncated) {
        return;
    }
    if (storage_lstat(path, st) != 0) {
        if (errno != ENOENT) {
            usage->truncated = true;
        }
        return;
    }
    if (S_ISREG(st->st_mode)) {
        if (*scanned >= STORAGE_SCAN_MAX_ENTRIES) {
            usage->truncated = true;
            return;
        }
        (*scanned)++;
        usage->files++;
        usage->logical += (uint64_t)st->st_size;
        usage->allocated += storage_allocated_size(st->st_size);
        return;
    }
    if (!S_ISDIR(st->st_mode)) {
        return;
    }
    if (depth >= STORAGE_SCAN_MAX_DEPTH) {
        usage->truncated = true;
        return;
    }

    DIR *dir = opendir(path);
    struct dirent *entry;
    bool read_error = false;
    if (!dir) {
        if (errno != ENOENT) {
            usage->truncated = true;
        }
        return;
    }
    while ((entry = storage_read_dir(dir, &read_error)) != NULL) {
        char *child = scratch->paths[depth + 1];

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!storage_join_child(child, STORAGE_PATH_MAX, path, entry->d_name)) {
            usage->truncated = true;
            break;
        }
        storage_scan_usage_path(depth + 1, scanned, usage, scratch);
        if (usage->truncated) {
            break;
        }
    }
    bool close_error = !storage_close_dir(dir);
    if (read_error || close_error) {
        usage->truncated = true;
    }
}

static void storage_scan_other(const char *root, size_t *scanned, storage_usage_t *usage,
                               storage_usage_scan_t *scratch)
{
    DIR *dir = opendir(root);
    struct dirent *entry;
    bool read_error = false;

    if (!dir) {
        usage->truncated = true;
        return;
    }

    while ((entry = storage_read_dir(dir, &read_error)) != NULL) {
        char *path = scratch->paths[0];

        if (entry->d_name[0] == '.' || storage_known_top_level(entry->d_name)) {
            continue;
        }
        if (snprintf(path, STORAGE_PATH_MAX, "%s/%s", root, entry->d_name) >= STORAGE_PATH_MAX) {
            usage->truncated = true;
            break;
        }
        storage_scan_usage_path(0, scanned, usage, scratch);
        if (usage->truncated) {
            break;
        }
    }
    bool close_error = !storage_close_dir(dir);
    if (read_error || close_error) {
        usage->truncated = true;
    }
}

static esp_err_t storage_status(char *output, size_t output_size)
{
    static const char *const names[] = {"sessions", "inbox", "memory", "skills", "apps"};
    const size_t usage_count = sizeof(names) / sizeof(names[0]) + 1;
    storage_usage_t *usage = NULL;
    const char *root = claw_paths_get(CLAW_PATH_DATA);
    uint64_t total = 0;
    uint64_t free_bytes = 0;
    size_t scanned = 0;
    size_t offset = 0;
    storage_usage_scan_t *scratch = NULL;
    esp_err_t err;

    if (!root || !root[0]) {
        storage_write(output, output_size, "Storage unavailable: DATA is not mounted.");
        return ESP_ERR_INVALID_STATE;
    }
    err = esp_vfs_fat_info(root, &total, &free_bytes);
    if (err != ESP_OK) {
        storage_write(output, output_size, "Storage unavailable: filesystem statistics failed.");
        return err;
    }
    scratch = calloc(1, sizeof(*scratch));
    usage = calloc(usage_count, sizeof(*usage));
    if (!scratch || !usage) {
        free(scratch);
        free(usage);
        storage_write(output, output_size, "Storage unavailable: out of memory.");
        return ESP_ERR_NO_MEM;
    }

    storage_append(output, output_size, &offset,
                   "Storage: total=%" PRIu64 " free=%" PRIu64 " reserve=%u state=%s\nAllocation unit: ",
                   total, free_bytes, (unsigned)CLAW_STORAGE_RESERVE_BYTES,
                   free_bytes < CLAW_STORAGE_RESERVE_BYTES ? "LOW" : "healthy");
    if (s_storage.reported_allocation_unit) {
        storage_append(output, output_size, &offset, "%zu\n", s_storage.reported_allocation_unit);
    } else {
        storage_append(output, output_size, &offset, "unknown\n");
    }

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char *path = scratch->paths[0];

        if (snprintf(path, STORAGE_PATH_MAX, "%s/%s", root, names[i]) < STORAGE_PATH_MAX) {
            storage_scan_usage_path(0, &scanned, &usage[i], scratch);
        } else {
            usage[i].truncated = true;
        }
        storage_append(output, output_size, &offset, "%s: logical=%" PRIu64 " ", names[i], usage[i].logical);
        if (s_storage.reported_allocation_unit) {
            storage_append(output, output_size, &offset, "allocated=%" PRIu64, usage[i].allocated);
        } else {
            storage_append(output, output_size, &offset, "allocated=unknown");
        }
        storage_append(output, output_size, &offset, " files=%zu%s\n", usage[i].files,
                       usage[i].truncated ? " (partial)" : "");
    }
    storage_scan_other(root, &scanned, &usage[sizeof(names) / sizeof(names[0])], scratch);
    storage_append(output, output_size, &offset, "other: logical=%" PRIu64 " ",
                   usage[sizeof(names) / sizeof(names[0])].logical);
    if (s_storage.reported_allocation_unit) {
        storage_append(output, output_size, &offset, "allocated=%" PRIu64,
                       usage[sizeof(names) / sizeof(names[0])].allocated);
    } else {
        storage_append(output, output_size, &offset, "allocated=unknown");
    }
    storage_append(output, output_size, &offset, " files=%zu%s",
                   usage[sizeof(names) / sizeof(names[0])].files,
                   usage[sizeof(names) / sizeof(names[0])].truncated ? " (partial)" : "");
    free(scratch);
    free(usage);
    return ESP_OK;
}

static bool storage_candidate_add(storage_candidate_set_t *set, const char *relative,
                                  const struct stat *st, storage_candidate_kind_t kind)
{
    storage_candidate_t *item;

    set->eligible_count++;
    if (set->count >= STORAGE_CANDIDATE_MAX) {
        return true;
    }
    item = &set->items[set->count++];
    if (snprintf(item->relative_path, sizeof(item->relative_path), "%s", relative) >=
            (int)sizeof(item->relative_path)) {
        set->count--;
        set->truncated = true;
        return false;
    }
    item->size = st->st_size;
    item->mtime = st->st_mtime;
    item->kind = kind;
    return true;
}

static void storage_scan_session_sidecars(const char *root, storage_candidate_set_t *set)
{
    storage_sidecar_scan_t *scratch = calloc(1, sizeof(*scratch));
    DIR *dir;
    struct dirent *entry;
    bool read_error = false;

    if (!scratch) {
        set->scan_error = true;
        return;
    }
    if (snprintf(scratch->sessions, sizeof(scratch->sessions), "%s/sessions", root) >=
            (int)sizeof(scratch->sessions)) {
        set->scan_error = true;
        free(scratch);
        return;
    }
    dir = opendir(scratch->sessions);
    if (!dir && errno != ENOENT) {
        set->scan_error = true;
        free(scratch);
        return;
    }
    while (dir && (entry = storage_read_dir(dir, &read_error)) != NULL) {
        struct stat *st = &scratch->stat_buf;
        bool lookup_error = false;
        size_t name_len = strlen(entry->d_name);
        size_t stem_len;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (++set->scanned > STORAGE_SCAN_MAX_ENTRIES) {
            set->truncated = true;
            break;
        }
        if (!storage_has_suffix(entry->d_name, ".skills.json")) {
            continue;
        }
        if (snprintf(scratch->path, sizeof(scratch->path), "%s/%s", scratch->sessions,
                     entry->d_name) >= (int)sizeof(scratch->path) ||
                snprintf(scratch->relative, sizeof(scratch->relative), "sessions/%s", entry->d_name) >=
                (int)sizeof(scratch->relative)) {
            set->scan_error = true;
            break;
        }
        if (storage_lstat(scratch->path, st) != 0) {
            set->scan_error = true;
            continue;
        }
        if (!S_ISREG(st->st_mode) ||
                !storage_old_enough(st->st_mtime, STORAGE_SAFE_MIN_AGE_SEC)) {
            continue;
        }
        stem_len = name_len - strlen(".skills.json");
        if (stem_len == 0 || snprintf(scratch->base, sizeof(scratch->base), "%s/%.*s",
                                     scratch->sessions, (int)stem_len, entry->d_name) >=
                (int)sizeof(scratch->base) ||
                snprintf(scratch->log_path, sizeof(scratch->log_path), "%s.log", scratch->base) >=
                (int)sizeof(scratch->log_path) ||
                snprintf(scratch->idx_path, sizeof(scratch->idx_path), "%s.log.idx", scratch->base) >=
                (int)sizeof(scratch->idx_path)) {
            set->scan_error = true;
            break;
        }
        if (!storage_path_absent(scratch->log_path, &lookup_error, &scratch->lookup_stat) ||
                !storage_path_absent(scratch->idx_path, &lookup_error, &scratch->lookup_stat)) {
            set->scan_error |= lookup_error;
            continue;
        }
        storage_candidate_add(set, scratch->relative, st, STORAGE_CANDIDATE_SIDECAR);
    }
    if (dir) {
        bool close_error = !storage_close_dir(dir);
        if (read_error || close_error) {
            set->scan_error = true;
        }
    }
    free(scratch);
}

static void storage_scan_inbox_recursive(const char *root, unsigned depth, bool attachments,
                                         storage_candidate_set_t *set, storage_inbox_scan_t *scratch)
{
    const char *relative = scratch->relative[depth];
    DIR *dir;
    struct dirent *entry;
    bool read_error = false;

    if (snprintf(scratch->full_path, sizeof(scratch->full_path), "%s/%s", root, relative) >=
            (int)sizeof(scratch->full_path)) {
        set->scan_error = true;
        return;
    }
    dir = opendir(scratch->full_path);
    if (!dir && errno != ENOENT) {
        set->scan_error = true;
        return;
    }
    while (dir && !set->truncated && (entry = storage_read_dir(dir, &read_error)) != NULL) {
        char *child_relative = scratch->relative[depth + 1];
        struct stat *st = &scratch->stat_buf[depth + 1];

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (++set->scanned > STORAGE_SCAN_MAX_ENTRIES) {
            set->truncated = true;
            break;
        }
        if (!storage_join_child(child_relative, STORAGE_PATH_MAX, relative, entry->d_name) ||
                snprintf(scratch->full_path, sizeof(scratch->full_path), "%s/%s", root,
                         child_relative) >= (int)sizeof(scratch->full_path)) {
            set->scan_error = true;
            break;
        }
        if (storage_lstat(scratch->full_path, st) != 0) {
            set->scan_error = true;
            continue;
        }
        if (S_ISDIR(st->st_mode)) {
            if (depth >= STORAGE_SCAN_MAX_DEPTH) {
                set->truncated = true;
            } else {
                storage_scan_inbox_recursive(root, depth + 1, attachments, set, scratch);
            }
            continue;
        }
        if (!S_ISREG(st->st_mode) || storage_has_suffix(entry->d_name, ".bak")) {
            continue;
        }
        if (attachments) {
            if (storage_has_suffix(entry->d_name, ".tmp") ||
                    !storage_old_enough(st->st_mtime, STORAGE_ATTACHMENT_MIN_AGE_SEC)) {
                continue;
            }
            storage_candidate_add(set, child_relative, st, STORAGE_CANDIDATE_ATTACHMENT);
        } else if (storage_has_suffix(entry->d_name, ".tmp") &&
                   storage_old_enough(st->st_mtime, STORAGE_SAFE_MIN_AGE_SEC)) {
            storage_candidate_add(set, child_relative, st, STORAGE_CANDIDATE_TEMP);
        }
    }
    if (dir) {
        bool close_error = !storage_close_dir(dir);
        if (read_error || close_error) {
            set->scan_error = true;
        }
    }
}

static esp_err_t storage_collect_candidates(const char *category, storage_candidate_set_t *set)
{
    const char *root = claw_paths_get(CLAW_PATH_DATA);
    storage_inbox_scan_t *scratch = NULL;

    memset(set, 0, sizeof(*set));
    if (!root || !root[0]) {
        return ESP_ERR_INVALID_STATE;
    }
    set->items = calloc(STORAGE_CANDIDATE_MAX, sizeof(*set->items));
    if (!set->items) {
        return ESP_ERR_NO_MEM;
    }
    scratch = calloc(1, sizeof(*scratch));
    if (!scratch) {
        free(set->items);
        memset(set, 0, sizeof(*set));
        return ESP_ERR_NO_MEM;
    }
    snprintf(scratch->relative[0], sizeof(scratch->relative[0]), "inbox");
    if (strcmp(category, "safe") == 0) {
        storage_scan_session_sidecars(root, set);
        storage_scan_inbox_recursive(root, 0, false, set, scratch);
    } else if (strcmp(category, "attachments") == 0) {
        storage_scan_inbox_recursive(root, 0, true, set, scratch);
    } else {
        free(scratch);
        free(set->items);
        memset(set, 0, sizeof(*set));
        return ESP_ERR_INVALID_ARG;
    }
    free(scratch);
    return ESP_OK;
}

static void storage_render_preview(const char *category, const storage_candidate_set_t *set,
                                   char *output, size_t output_size)
{
    size_t offset = 0;
    uint64_t logical = 0;
    uint64_t allocated = 0;

    for (size_t i = 0; i < set->count; i++) {
        logical += (uint64_t)set->items[i].size;
        allocated += storage_allocated_size(set->items[i].size);
    }
    storage_append(output, output_size, &offset,
                   "Storage cleanup preview (%s): batch=%zu eligible=%zu logical=%" PRIu64 " ",
                   category, set->count, set->eligible_count, logical);
    if (s_storage.reported_allocation_unit) {
        storage_append(output, output_size, &offset, "allocated=%" PRIu64, allocated);
    } else {
        storage_append(output, output_size, &offset, "allocated=unknown");
    }
    storage_append(output, output_size, &offset, "%s%s",
                   set->truncated ? " scan=partial" : "",
                   set->scan_error ? " scan=error" : "");
    for (size_t i = 0; i < set->count; i++) {
        storage_append(output, output_size, &offset, "\n- %s (%jd bytes)",
                       set->items[i].relative_path, (intmax_t)set->items[i].size);
    }
    if (set->eligible_count > set->count) {
        storage_append(output, output_size, &offset,
                       "\nOnly this batch is selected; repeat cleanup for %zu remaining files.",
                       set->eligible_count - set->count);
    }
}

static bool storage_direct_telegram(const claw_cap_call_context_t *ctx)
{
    return ctx && ctx->caller == CLAW_CAP_CALLER_SYSTEM && ctx->channel &&
           strcmp(ctx->channel, "telegram") == 0 && ctx->chat_id && ctx->chat_id[0] &&
           ctx->source_cap && strcmp(ctx->source_cap, "tg_gateway") == 0;
}

static uint32_t storage_random_value(void)
{
#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
    return 0x51a7c000U ^ ++s_storage.token_counter;
#else
    return esp_random() ^ ++s_storage.token_counter;
#endif
}

static uint64_t storage_monotonic_ms(void)
{
#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
#else
    return (uint64_t)esp_timer_get_time() / 1000U;
#endif
}

static void storage_pending_clear_locked(void)
{
    free(s_storage.pending.items);
    memset(&s_storage.pending, 0, sizeof(s_storage.pending));
}

static esp_err_t storage_create_pending(storage_pending_kind_t kind, storage_candidate_set_t *set,
                                        const claw_cap_call_context_t *ctx, char *token, size_t token_size)
{
    if (!storage_direct_telegram(ctx) || !token || token_size < sizeof(s_storage.pending.token)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!storage_lock()) {
        return ESP_ERR_NO_MEM;
    }
    storage_pending_clear_locked();
    s_storage.pending.kind = kind;
    if (set) {
        s_storage.pending.items = set->items;
        s_storage.pending.count = set->count;
        set->items = NULL;
        set->count = 0;
    }
    snprintf(s_storage.pending.token, sizeof(s_storage.pending.token), "%08" PRIx32 "%08" PRIx32,
             storage_random_value(), storage_random_value());
    snprintf(s_storage.pending.channel, sizeof(s_storage.pending.channel), "%s", ctx->channel);
    snprintf(s_storage.pending.chat_id, sizeof(s_storage.pending.chat_id), "%s", ctx->chat_id);
    s_storage.pending.expires_at_ms = storage_monotonic_ms() + (uint64_t)STORAGE_TOKEN_TTL_SEC * 1000U;
    snprintf(token, token_size, "%s", s_storage.pending.token);
    storage_unlock();
    return ESP_OK;
}

static bool storage_relative_path_safe(const storage_candidate_t *item)
{
    if (!item || strstr(item->relative_path, "..") || item->relative_path[0] == '/') {
        return false;
    }
    if (item->kind == STORAGE_CANDIDATE_SIDECAR) {
        return strncmp(item->relative_path, "sessions/", 9) == 0 &&
               strchr(item->relative_path + 9, '/') == NULL &&
               storage_has_suffix(item->relative_path, ".skills.json");
    }
    return strncmp(item->relative_path, "inbox/", 6) == 0;
}

static bool storage_candidate_still_eligible(const char *root, const storage_candidate_t *item,
                                             char *path, size_t path_size)
{
    storage_revalidate_t *scratch = calloc(1, sizeof(*scratch));
    bool eligible = false;

    if (!scratch || !storage_relative_path_safe(item) ||
            snprintf(path, path_size, "%s/%s", root, item->relative_path) >= (int)path_size ||
            storage_lstat(path, &scratch->stat_buf) != 0 || !S_ISREG(scratch->stat_buf.st_mode) ||
            scratch->stat_buf.st_size != item->size || scratch->stat_buf.st_mtime != item->mtime) {
        free(scratch);
        return false;
    }
    if (item->kind == STORAGE_CANDIDATE_SIDECAR) {
        size_t len = strlen(path) - strlen(".skills.json");
        bool absent;

        if (len >= STORAGE_PATH_MAX) {
            free(scratch);
            return false;
        }
        if (snprintf(scratch->sibling, STORAGE_PATH_MAX, "%.*s.log", (int)len, path) >=
                STORAGE_PATH_MAX) {
            free(scratch);
            return false;
        }
        absent = storage_path_absent(scratch->sibling, NULL, &scratch->stat_buf);
        if (absent && snprintf(scratch->sibling, STORAGE_PATH_MAX, "%.*s.log.idx", (int)len, path) <
                STORAGE_PATH_MAX) {
            absent = storage_path_absent(scratch->sibling, NULL, &scratch->stat_buf);
        } else {
            absent = false;
        }
        eligible = absent && storage_old_enough(item->mtime, STORAGE_SAFE_MIN_AGE_SEC);
    } else if (item->kind == STORAGE_CANDIDATE_TEMP) {
        eligible = storage_has_suffix(path, ".tmp") && !storage_has_suffix(path, ".bak") &&
                   storage_old_enough(item->mtime, STORAGE_SAFE_MIN_AGE_SEC);
    } else {
        eligible = !storage_has_suffix(path, ".tmp") && !storage_has_suffix(path, ".bak") &&
                   storage_old_enough(item->mtime, STORAGE_ATTACHMENT_MIN_AGE_SEC);
    }
    free(scratch);
    return eligible;
}

static void storage_delete_candidates(storage_candidate_t *items, size_t count,
                                      char *output, size_t output_size)
{
    const char *root = claw_paths_get(CLAW_PATH_DATA);
    uint64_t total_before = 0;
    uint64_t free_before = 0;
    uint64_t total_after = 0;
    uint64_t free_after = 0;
    size_t deleted = 0;
    size_t changed = 0;
    size_t errors = 0;
    uint64_t logical = 0;
    char *path = NULL;
    char free_delta[32];

    if (!root || !root[0]) {
        storage_write(output, output_size, "Cleanup failed: DATA is not mounted.");
        return;
    }
    path = malloc(STORAGE_PATH_MAX);
    if (!path) {
        storage_write(output, output_size, "Cleanup failed: out of memory.");
        return;
    }
    esp_err_t before_err = esp_vfs_fat_info(root, &total_before, &free_before);
    for (size_t i = 0; i < count; i++) {
        if (!storage_candidate_still_eligible(root, &items[i], path, STORAGE_PATH_MAX)) {
            changed++;
            continue;
        }
        if (unlink(path) == 0) {
            deleted++;
            logical += (uint64_t)items[i].size;
        } else {
            errors++;
        }
    }
    esp_err_t after_err = esp_vfs_fat_info(root, &total_after, &free_after);
    if (before_err == ESP_OK && after_err == ESP_OK) {
        snprintf(free_delta, sizeof(free_delta), "%" PRIu64,
                 free_after > free_before ? free_after - free_before : 0);
    } else {
        snprintf(free_delta, sizeof(free_delta), "unknown");
    }
    storage_write(output, output_size,
                  "Cleanup complete: deleted=%zu changed=%zu errors=%zu logical=%" PRIu64
                  " free_delta=%s.", deleted, changed, errors, logical, free_delta);
    free(path);
}

static esp_err_t storage_confirm(const char *token, const claw_cap_call_context_t *ctx,
                                 char *output, size_t output_size)
{
    storage_pending_t pending = {0};
    uint64_t now_ms = storage_monotonic_ms();

    if (!storage_direct_telegram(ctx)) {
        storage_write(output, output_size, "Confirmation requires a direct Telegram /storage command.");
        return ESP_OK;
    }
    if (!storage_lock()) {
        return ESP_ERR_NO_MEM;
    }
    if (s_storage.pending.kind == STORAGE_PENDING_NONE || !token ||
            strcmp(token, s_storage.pending.token) != 0) {
        storage_unlock();
        storage_write(output, output_size, "Unknown or expired storage confirmation token.");
        return ESP_OK;
    }
    if (now_ms > s_storage.pending.expires_at_ms) {
        storage_pending_clear_locked();
        storage_unlock();
        storage_write(output, output_size, "Storage confirmation token expired. Run /storage clean again.");
        return ESP_OK;
    }
    if (strcmp(ctx->channel, s_storage.pending.channel) != 0 ||
            strcmp(ctx->chat_id, s_storage.pending.chat_id) != 0) {
        storage_unlock();
        storage_write(output, output_size, "Storage confirmation token does not belong to this chat.");
        return ESP_OK;
    }
    pending = s_storage.pending;
    memset(&s_storage.pending, 0, sizeof(s_storage.pending));
    storage_unlock();

    if (pending.kind == STORAGE_PENDING_REPAIR) {
        esp_err_t err = claw_memory_storage_check(true, output, output_size);
        free(pending.items);
        return err;
    }
    storage_delete_candidates(pending.items, pending.count, output, output_size);
    free(pending.items);
    return ESP_OK;
}

static esp_err_t storage_preview_or_clean(const char *category, bool clean,
                                          const claw_cap_call_context_t *ctx,
                                          char *output, size_t output_size)
{
    storage_candidate_set_t set;
    char token[17];
    size_t offset;
    esp_err_t err;

    if (clean && !storage_direct_telegram(ctx)) {
        storage_write(output, output_size, "Cleanup requires a direct Telegram /storage command.");
        return ESP_OK;
    }
    err = storage_collect_candidates(category, &set);
    if (err != ESP_OK) {
        storage_write(output, output_size,
                      "Usage: /storage preview [safe|attachments] or /storage clean [safe|attachments]");
        return err == ESP_ERR_INVALID_ARG ? ESP_OK : err;
    }
    storage_render_preview(category, &set, output, output_size);
    if (!clean) {
        free(set.items);
        return ESP_OK;
    }
    if (set.truncated || set.scan_error) {
        size_t len = strlen(output);
        storage_append(output, output_size, &len,
                       "\nCleanup refused because the filesystem scan was incomplete.");
        free(set.items);
        return ESP_OK;
    }
    if (set.count == 0) {
        free(set.items);
        return ESP_OK;
    }
    err = storage_create_pending(STORAGE_PENDING_FILES, &set, ctx, token, sizeof(token));
    free(set.items);
    if (err != ESP_OK) {
        return err;
    }
    offset = strlen(output);
    storage_append(output, output_size, &offset,
                   "\nConfirm within 5 minutes with /storage confirm %s", token);
    return ESP_OK;
}

static esp_err_t storage_check(char *output, size_t output_size)
{
    esp_err_t err = claw_memory_storage_check(false, output, output_size);

    if (err != ESP_OK && !output[0]) {
        storage_write(output, output_size, "Memory index check unavailable (%s).", esp_err_to_name(err));
    }
    return err;
}

static esp_err_t storage_repair(const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    char token[17];
    esp_err_t err;

    if (!storage_direct_telegram(ctx)) {
        storage_write(output, output_size, "Repair requires a direct Telegram /storage command.");
        return ESP_OK;
    }
    err = storage_create_pending(STORAGE_PENDING_REPAIR, NULL, ctx, token, sizeof(token));
    if (err != ESP_OK) {
        return err;
    }
    storage_write(output, output_size,
                  "Memory index repair requested. Confirm within 5 minutes with /storage confirm %s", token);
    return ESP_OK;
}

static void storage_parse_command(const char *input_json, char *command, size_t command_size)
{
    cJSON *root = input_json && input_json[0] ? cJSON_Parse(input_json) : NULL;
    const cJSON *item = root ? cJSON_GetObjectItemCaseSensitive(root, "command") : NULL;
    const char *value = cJSON_IsString(item) ? item->valuestring : "";
    size_t len;

    while (*value == ' ' || *value == '\t') {
        value++;
    }
    snprintf(command, command_size, "%s", value);
    len = strlen(command);
    while (len > 0 && (command[len - 1] == ' ' || command[len - 1] == '\t')) {
        command[--len] = '\0';
    }
    cJSON_Delete(root);
}

esp_err_t cap_system_storage_execute(const char *input_json,
                                     const claw_cap_call_context_t *ctx,
                                     char *output,
                                     size_t output_size)
{
    char command[96];
    char *argument;

    if (!output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    output[0] = '\0';
    storage_parse_command(input_json, command, sizeof(command));
    argument = strchr(command, ' ');
    if (argument) {
        *argument++ = '\0';
        while (*argument == ' ') {
            argument++;
        }
    }
    if (!command[0] || strcmp(command, "status") == 0) {
        return storage_status(output, output_size);
    }
    if (strcmp(command, "preview") == 0) {
        return storage_preview_or_clean(argument && argument[0] ? argument : "safe", false,
                                        ctx, output, output_size);
    }
    if (strcmp(command, "clean") == 0) {
        return storage_preview_or_clean(argument && argument[0] ? argument : "safe", true,
                                        ctx, output, output_size);
    }
    if (strcmp(command, "confirm") == 0 && argument && argument[0]) {
        return storage_confirm(argument, ctx, output, output_size);
    }
    if (strcmp(command, "check") == 0 && (!argument || !argument[0])) {
        return storage_check(output, output_size);
    }
    if (strcmp(command, "repair") == 0 && (!argument || !argument[0])) {
        return storage_repair(ctx, output, output_size);
    }
    storage_write(output, output_size,
                  "Storage commands:\n"
                  "/storage [status]\n"
                  "/storage preview [safe|attachments]\n"
                  "/storage clean [safe|attachments]\n"
                  "/storage check\n/storage repair\n/storage confirm <token>");
    return ESP_OK;
}

void cap_system_storage_set_allocation_unit(size_t bytes)
{
    s_storage.reported_allocation_unit = bytes;
    claw_storage_set_allocation_unit(bytes);
}

esp_err_t cap_system_storage_init(void)
{
#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
    return ESP_OK;
#else
    if (s_storage.mutex) {
        return ESP_OK;
    }
    s_storage.mutex = xSemaphoreCreateMutex();
    return s_storage.mutex ? ESP_OK : ESP_ERR_NO_MEM;
#endif
}

#ifndef CAP_SYSTEM_STORAGE_HOST_TEST
static void storage_auto_cleanup_if_low(void)
{
    const char *root = claw_paths_get(CLAW_PATH_DATA);
    storage_candidate_set_t set;
    uint64_t total = 0;
    uint64_t free_bytes = 0;
    size_t deleted = 0;
    char *path = NULL;

    if (!root || esp_vfs_fat_info(root, &total, &free_bytes) != ESP_OK ||
            free_bytes >= CLAW_STORAGE_RESERVE_BYTES ||
            storage_collect_candidates("safe", &set) != ESP_OK) {
        return;
    }
    if (set.truncated || set.scan_error) {
        ESP_LOGW(TAG, "Low-space orphan cleanup skipped: scan was partial");
        free(set.items);
        return;
    }
    path = malloc(STORAGE_PATH_MAX);
    if (!path) {
        free(set.items);
        return;
    }
    for (size_t i = 0; i < set.count && free_bytes < CLAW_STORAGE_RESERVE_BYTES; i++) {
        if (set.items[i].kind != STORAGE_CANDIDATE_SIDECAR ||
                !storage_candidate_still_eligible(root, &set.items[i], path, STORAGE_PATH_MAX)) {
            continue;
        }
        if (unlink(path) == 0) {
            deleted++;
            esp_vfs_fat_info(root, &total, &free_bytes);
        }
    }
    if (deleted) {
        ESP_LOGW(TAG, "Low-space cleanup removed %zu orphan session sidecars; free=%" PRIu64,
                 deleted, free_bytes);
    }
    free(path);
    free(set.items);
}

static void storage_monitor_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(STORAGE_MONITOR_INITIAL_MS));
    for (;;) {
        storage_auto_cleanup_if_low();
        vTaskDelay(pdMS_TO_TICKS(STORAGE_MONITOR_PERIOD_MS));
    }
}
#endif

esp_err_t cap_system_storage_start_monitor(void)
{
#ifdef CAP_SYSTEM_STORAGE_HOST_TEST
    return ESP_OK;
#else
    BaseType_t created;
    esp_err_t err = cap_system_storage_init();

    if (err != ESP_OK) {
        return err;
    }

    if (s_storage.monitor_started) {
        return ESP_OK;
    }
    created = claw_task_create(&(claw_task_config_t) {
                                   .name = "storage_monitor",
                                   .stack_size = 4096,
                                   .priority = 2,
                                   .core_id = tskNO_AFFINITY,
                                   .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                               },
                               storage_monitor_task, NULL, NULL);
    if (created != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    s_storage.monitor_started = true;
    return ESP_OK;
#endif
}
