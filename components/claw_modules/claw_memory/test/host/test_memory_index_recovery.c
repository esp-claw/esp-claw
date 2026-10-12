/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host failure-injection tests for recoverable memory-index replacement. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "claw_memory_internal.h"

static int s_failures;
static FILE *s_tmp_file;
static bool s_fail_tmp_close;
static bool s_fail_tmp_promote;
static bool s_fail_backup_promote;
static bool s_fail_records_backup_promote;

static void remove_index_sidecars(void);

static const char LEGACY_RECORD_KEPT[] =
    "{\"id\":\"kept\",\"source\":\"test\",\"content\":\"saved\",\"tags\":\"\","
    "\"keywords\":\"\",\"created_at\":1,\"updated_at\":1,\"access_count\":0,"
    "\"deleted\":false,\"summary_ids\":[]}\n";
static const char LEGACY_RECORD_PROJECT[] =
    "{\"id\":\"m1\",\"source\":\"test\",\"content\":\"ESP32 project\","
    "\"tags\":\"project\",\"keywords\":\"esp32\",\"created_at\":1,\"updated_at\":1,"
    "\"access_count\":0,\"deleted\":false,\"summary_ids\":[7]}\n";

#define CHECK(cond) do { \
        if (!(cond)) { \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            s_failures++; \
        } \
    } while (0)

claw_memory_state_t s_memory;

void claw_memory_lock(void) {}
void claw_memory_unlock(void) {}

FILE *__real_fopen(const char *path, const char *mode);
int __real_fclose(FILE *file);
int __real_rename(const char *old_path, const char *new_path);

static bool has_suffix(const char *text, const char *suffix)
{
    size_t text_len = strlen(text);
    size_t suffix_len = strlen(suffix);

    return text_len >= suffix_len && strcmp(text + text_len - suffix_len, suffix) == 0;
}

FILE *__wrap_fopen(const char *path, const char *mode)
{
    FILE *file = __real_fopen(path, mode);

    if (file && has_suffix(path, ".tmp") && mode[0] == 'w') {
        s_tmp_file = file;
    }
    return file;
}

int __wrap_fclose(FILE *file)
{
    bool fail = s_fail_tmp_close && file == s_tmp_file;
    int rc = __real_fclose(file);

    if (file == s_tmp_file) {
        s_tmp_file = NULL;
    }
    if (fail) {
        s_fail_tmp_close = false;
        errno = ENOSPC;
        return EOF;
    }
    return rc;
}

int __wrap_rename(const char *old_path, const char *new_path)
{
    if (s_fail_tmp_promote && has_suffix(old_path, ".tmp") &&
        strcmp(new_path, s_memory.index_path) == 0) {
        s_fail_tmp_promote = false;
        errno = EIO;
        return -1;
    }
    if (s_fail_backup_promote && has_suffix(old_path, ".bak") &&
        strcmp(new_path, s_memory.index_path) == 0) {
        s_fail_backup_promote = false;
        errno = EIO;
        return -1;
    }
    if (s_fail_records_backup_promote && has_suffix(old_path, ".bak") &&
        strcmp(new_path, s_memory.records_path) == 0) {
        s_fail_records_backup_promote = false;
        errno = EIO;
        return -1;
    }
    return __real_rename(old_path, new_path);
}

static void write_text(const char *path, const char *text)
{
    FILE *file = __real_fopen(path, "wb");

    CHECK(file != NULL);
    if (file) {
        CHECK(fputs(text, file) >= 0);
        CHECK(__real_fclose(file) == 0);
    }
}

static void write_bytes(const char *path, const void *data, size_t size)
{
    FILE *file = __real_fopen(path, "wb");

    CHECK(file != NULL);
    if (file) {
        CHECK(fwrite(data, 1, size, file) == size);
        CHECK(__real_fclose(file) == 0);
    }
}

static char *read_text(const char *path)
{
    char *text = NULL;

    CHECK(read_file_dup(path, &text) == ESP_OK);
    return text;
}

static cJSON *make_index(int version)
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "version", version);
    cJSON_AddNumberToObject(root, "next_summary_id", 1);
    cJSON_AddNumberToObject(root, "last_compact_digest_size", 0);
    cJSON_AddItemToObject(root, "summaries", cJSON_CreateArray());
    cJSON_AddItemToObject(root, "keyword_index", cJSON_CreateObject());
    return root;
}

/* A delayed ENOSPC from fclose must leave the previous index byte-for-byte intact. */
static void test_close_failure_preserves_index(void)
{
    const char *old_text = "{\"version\":3,\"marker\":\"old\",\"summaries\":[],\"keyword_index\":{}}";
    cJSON *replacement = make_index(4);
    char *actual;

    write_text(s_memory.index_path, old_text);
    s_fail_tmp_close = true;
    CHECK(claw_memory_save_index(replacement) != ESP_OK);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, old_text) == 0);
    free(actual);
    cJSON_Delete(replacement);
}

/* A FAT rename failure after old->bak must restore the prior valid index. */
static void test_promote_failure_restores_index(void)
{
    const char *old_text = "{\"version\":3,\"marker\":\"old\",\"summaries\":[],\"keyword_index\":{}}";
    cJSON *replacement = make_index(4);
    char *actual;

    write_text(s_memory.index_path, old_text);
    s_fail_tmp_promote = true;
    CHECK(claw_memory_save_index(replacement) != ESP_OK);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, old_text) == 0);
    free(actual);
    cJSON_Delete(replacement);
}

/* Reboot between old->bak and tmp->target must resume the complete new index. */
static void test_load_recovers_interrupted_replace(void)
{
    char tmp_path[256];
    char bak_path[256];
    cJSON *root = NULL;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", s_memory.index_path);
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    unlink(s_memory.index_path);
    write_text(bak_path,
               "{\"version\":3,\"next_summary_id\":1,\"last_compact_digest_size\":0,"
               "\"marker\":\"old\",\"summaries\":[],\"keyword_index\":{}}");
    write_text(tmp_path,
               "{\"version\":3,\"next_summary_id\":4,\"last_compact_digest_size\":0,"
               "\"marker\":\"new\",\"summaries\":[],\"keyword_index\":{}}");

    CHECK(claw_memory_load_index(&root) == ESP_OK);
    CHECK(root && cJSON_GetNumberValue(cJSON_GetObjectItem(root, "next_summary_id")) == 4);
    CHECK(access(s_memory.index_path, F_OK) == 0);
    cJSON_Delete(root);
}

/* Boot recovery runs before default seeding, so a backup cannot be hidden by an empty index. */
static void test_prepare_before_default_preserves_backup(void)
{
    char bak_path[256];
    char *actual;
    const char *backup =
        "{\"version\":3,\"next_summary_id\":6,\"last_compact_digest_size\":0,"
        "\"summaries\":[],\"keyword_index\":{}}";

    remove_index_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    write_text(bak_path, backup);
    CHECK(claw_memory_index_prepare_for_default() == ESP_OK);
    CHECK(ensure_file_with_default(s_memory.index_path,
                                   "{\"version\":3,\"next_summary_id\":1,"
                                   "\"last_compact_digest_size\":0,\"summaries\":[],"
                                   "\"keyword_index\":{}}") == ESP_OK);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, backup) == 0);
    free(actual);
}

/* A partial tmp file must be ignored in favor of the prior valid backup. */
static void test_load_falls_back_from_partial_tmp(void)
{
    char tmp_path[256];
    char bak_path[256];
    cJSON *root = NULL;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", s_memory.index_path);
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    unlink(s_memory.index_path);
    write_text(tmp_path, "{\"version\":4");
    write_text(bak_path,
               "{\"version\":3,\"next_summary_id\":1,\"last_compact_digest_size\":0,"
               "\"marker\":\"old\",\"summaries\":[],\"keyword_index\":{}}");

    CHECK(claw_memory_load_index(&root) == ESP_OK);
    CHECK(root && cJSON_GetNumberValue(cJSON_GetObjectItem(root, "version")) == 3);
    CHECK(access(s_memory.index_path, F_OK) == 0);
    cJSON_Delete(root);
}

/* A parseable but incomplete primary must not outrank a complete valid backup. */
static void test_load_rejects_incomplete_primary_index(void)
{
    char bak_path[256];
    char corrupt_path[256];
    cJSON *root = NULL;

    remove_index_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    write_text(s_memory.index_path, "{\"version\":3}");
    write_text(bak_path,
               "{\"version\":3,\"next_summary_id\":9,\"last_compact_digest_size\":0,"
               "\"marker\":\"backup\",\"summaries\":[],\"keyword_index\":{}}");

    CHECK(claw_memory_load_index(&root) == ESP_OK);
    CHECK(root && cJSON_GetNumberValue(cJSON_GetObjectItem(root, "next_summary_id")) == 9);
    snprintf(corrupt_path, sizeof(corrupt_path), "%s.corrupt", s_memory.index_path);
    CHECK(access(corrupt_path, F_OK) == 0);
    cJSON_Delete(root);
}

/* Failed backup promotion restores the corrupt primary and keeps the valid backup. */
static void test_load_promotion_failure_preserves_all_copies(void)
{
    const char *corrupt = "{\"version\":3}";
    char bak_path[256];
    char *actual;
    cJSON *root = NULL;

    remove_index_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    write_text(s_memory.index_path, corrupt);
    write_text(bak_path,
               "{\"version\":3,\"next_summary_id\":2,\"last_compact_digest_size\":0,"
               "\"summaries\":[],\"keyword_index\":{}}");
    s_fail_backup_promote = true;
    CHECK(claw_memory_load_index(&root) != ESP_OK);
    CHECK(root == NULL);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
    CHECK(access(bak_path, F_OK) == 0);
}

/* Embedded NUL plus trailing bytes cannot make a damaged primary outrank its backup. */
static void test_index_validation_rejects_embedded_nul_tail(void)
{
    static const char bytes[] =
        "{\"version\":3,\"next_summary_id\":1,\"last_compact_digest_size\":0,"
        "\"summaries\":[],\"keyword_index\":{}}\0torn";
    char bak_path[256];
    cJSON *root = NULL;

    remove_index_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.index_path);
    write_bytes(s_memory.index_path, bytes, sizeof(bytes) - 1);
    write_text(bak_path,
               "{\"version\":3,\"next_summary_id\":8,\"last_compact_digest_size\":0,"
               "\"summaries\":[],\"keyword_index\":{}}");
    CHECK(claw_memory_load_index(&root) == ESP_OK);
    CHECK(root && cJSON_GetNumberValue(cJSON_GetObjectItem(root, "next_summary_id")) == 8);
    cJSON_Delete(root);
}

static void remove_index_sidecars(void)
{
    static const char *const suffixes[] = {"", ".tmp", ".old", ".bak", ".corrupt"};
    size_t i;

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        char path[256];

        snprintf(path, sizeof(path), "%s%s", s_memory.index_path, suffixes[i]);
        unlink(path);
    }
}

/* Inspection reports damage without renaming, deleting or rewriting any file. */
static void test_check_is_read_only(void)
{
    const char *corrupt = "{\"version\":3";
    char output[256];
    char *actual;

    remove_index_sidecars();
    write_text(s_memory.index_path, corrupt);
    write_text(s_memory.records_path, LEGACY_RECORD_PROJECT);

    CHECK(claw_memory_storage_check(false, output, sizeof(output)) == ESP_OK);
    CHECK(strstr(output, "damaged") != NULL);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
}

/* Repair archives the corrupt index and rebuilds summary labels with their recorded IDs. */
static void test_repair_rebuilds_index_from_complete_records(void)
{
    char corrupt_path[256];
    char output[256];
    cJSON *root = NULL;
    cJSON *summary;

    remove_index_sidecars();
    write_text(s_memory.index_path, "{\"version\":3");
    write_text(s_memory.records_path, LEGACY_RECORD_PROJECT);

    s_memory.initialized = 0;
    s_memory.storage_degraded = true;
    s_memory.storage_repair_required = true;
    CHECK(claw_memory_storage_check(true, output, sizeof(output)) == ESP_OK);
    CHECK(strstr(output, "repaired") != NULL);
    CHECK(strstr(output, "Restart the device") != NULL);
    s_memory.storage_degraded = false;
    s_memory.storage_repair_required = false;
    s_memory.initialized = 1;
    snprintf(corrupt_path, sizeof(corrupt_path), "%s.corrupt", s_memory.index_path);
    CHECK(access(corrupt_path, F_OK) == 0);
    CHECK(claw_memory_load_index(&root) == ESP_OK);
    summary = root ? claw_memory_find_summary_by_id(root, 7) : NULL;
    CHECK(summary != NULL);
    CHECK(summary && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(summary, "label")),
                            "project") == 0);
    cJSON_Delete(root);
}

/* An unusable records file makes reconstruction unsafe and leaves the corrupt index untouched. */
static void test_repair_rejects_incomplete_records(void)
{
    const char *corrupt = "{\"version\":3";
    char output[256];
    char *actual;

    remove_index_sidecars();
    write_text(s_memory.index_path, corrupt);
    write_text(s_memory.records_path, "{\"id\":\"m1\"}\n");

    CHECK(claw_memory_storage_check(true, output, sizeof(output)) == ESP_ERR_INVALID_STATE);
    CHECK(strstr(output, "incomplete") != NULL || strstr(output, "malformed") != NULL ||
          strstr(output, "records damaged") != NULL);
    actual = read_text(s_memory.index_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
}

static void remove_record_sidecars(void)
{
    static const char *const suffixes[] = {"", ".tmp", ".old", ".bak", ".corrupt"};
    size_t i;

    for (i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++) {
        char path[256];

        snprintf(path, sizeof(path), "%s%s", s_memory.records_path, suffixes[i]);
        unlink(path);
    }
}

/* Compaction must leave durable records untouched when temp-file close reports ENOSPC. */
static void test_record_snapshot_close_failure_preserves_records(void)
{
    const char *old_text = "{\"id\":\"old\",\"summary_ids\":[]}\n";
    claw_memory_item_t item = {.id = "new", .content = "replacement"};
    claw_memory_item_list_t items = {.items = &item, .count = 1, .capacity = 1};
    char *actual;

    remove_record_sidecars();
    write_text(s_memory.records_path, old_text);
    s_fail_tmp_close = true;
    CHECK(claw_memory_records_write_snapshot(&items) != ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, old_text) == 0);
    free(actual);
}

/* Escaped fixed-size fields can exceed the old 512-byte estimate and must remain complete. */
static void test_record_snapshot_serializes_large_record(void)
{
    claw_memory_item_t item = {.id = "large", .source = "test"};
    claw_memory_item_list_t items = {.items = &item, .count = 1, .capacity = 1};
    claw_memory_item_list_t loaded = {0};
    char *actual;
    cJSON *json;
    size_t i;

    for (i = 0; i + 1 < sizeof(item.content); i++) {
        item.content[i] = i % 2 ? '\\' : '"';
    }
    for (i = 0; i + 1 < sizeof(item.keywords); i++) {
        item.keywords[i] = i % 2 ? '\\' : '"';
    }
    for (i = 0; i + 1 < sizeof(item.tags); i++) {
        item.tags[i] = i % 2 ? '\\' : '"';
    }
    remove_record_sidecars();
    CHECK(claw_memory_records_write_snapshot(&items) == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strlen(actual) > 512);
    json = actual ? cJSON_ParseWithOpts(actual, NULL, false) : NULL;
    CHECK(json != NULL);
    CHECK(json && strcmp(cJSON_GetStringValue(cJSON_GetObjectItem(json, "content")),
                         item.content) == 0);
    CHECK(claw_memory_load_current_items(&loaded) == ESP_OK);
    CHECK(loaded.count == 1);
    CHECK(loaded.count == 1 && strcmp(loaded.items[0].content, item.content) == 0);
    claw_memory_item_list_free(&loaded);
    cJSON_Delete(json);
    free(actual);
}

/* Reboot after target->old must restore a fully valid JSONL snapshot before loading. */
static void test_record_snapshot_recovers_interrupted_replace(void)
{
    char old_path[256];
    char *actual;
    const char *old_text = LEGACY_RECORD_KEPT;

    remove_record_sidecars();
    snprintf(old_path, sizeof(old_path), "%s.old", s_memory.records_path);
    write_text(old_path, old_text);
    CHECK(claw_memory_records_prepare_for_default() == ESP_OK);
    CHECK(ensure_file_with_default(s_memory.records_path, "") == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, old_text) == 0);
    free(actual);
}

/* An unusable primary is never replaced by .bak on load; only explicit repair promotes it. */
static void test_record_recovery_archives_malformed_primary(void)
{
    const char *corrupt = "{\"id\":\"x\"}\n";
    const char *backup = LEGACY_RECORD_KEPT;
    char bak_path[256];
    char corrupt_path[256];
    char output[256];
    bool healthy = false;
    char *actual;

    remove_record_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.records_path);
    snprintf(corrupt_path, sizeof(corrupt_path), "%s.corrupt", s_memory.records_path);
    write_text(s_memory.records_path, corrupt);
    write_text(bak_path, backup);
    CHECK(claw_memory_records_prepare_for_read() == ESP_ERR_INVALID_STATE);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
    CHECK(access(bak_path, F_OK) == 0);

    CHECK(claw_memory_records_check(true, &healthy, output, sizeof(output)) == ESP_OK);
    CHECK(healthy);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, backup) == 0);
    free(actual);
    actual = read_text(corrupt_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
}

/* Failed promotion restores the unusable primary and retains the valid backup. */
static void test_record_recovery_failure_preserves_all_copies(void)
{
    const char *corrupt = "{\"id\":\"latest\"}\n";
    char bak_path[256];
    char output[256];
    bool healthy = false;
    char *actual;

    remove_record_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.records_path);
    write_text(s_memory.records_path, corrupt);
    write_text(bak_path, LEGACY_RECORD_KEPT);
    s_fail_records_backup_promote = true;
    CHECK(claw_memory_records_check(true, &healthy, output, sizeof(output)) != ESP_OK);
    CHECK(!healthy);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, corrupt) == 0);
    free(actual);
    CHECK(access(bak_path, F_OK) == 0);
}

/* A torn last line is truncated; earlier records stay and .bak is not used. */
static void test_record_torn_tail_is_truncated(void)
{
    char bak_path[256];
    char *actual;
    char *expected;

    remove_record_sidecars();
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.records_path);
    expected = dup_printf("%s%s", LEGACY_RECORD_KEPT, LEGACY_RECORD_PROJECT);
    actual = dup_printf("%s%s", expected, "{\"id\":\"torn\",\"sou");
    write_text(s_memory.records_path, actual);
    free(actual);
    write_text(bak_path, LEGACY_RECORD_KEPT);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, expected) == 0);
    free(actual);
    free(expected);
    actual = read_text(bak_path);
    CHECK(actual && strcmp(actual, LEGACY_RECORD_KEPT) == 0);
    free(actual);
}

/* An invalid complete line is skipped by the loader without degrading memory. */
static void test_record_invalid_middle_line_is_skipped(void)
{
    claw_memory_item_list_t list = {0};
    char *text;

    remove_record_sidecars();
    text = dup_printf("%s{\"id\":\"bad\"}\nnot json\n%s", LEGACY_RECORD_KEPT, LEGACY_RECORD_PROJECT);
    write_text(s_memory.records_path, text);
    free(text);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
    CHECK(claw_memory_load_current_items(&list) == ESP_OK);
    CHECK(claw_memory_find_item_index(&list, "kept") >= 0);
    CHECK(claw_memory_find_item_index(&list, "m1") >= 0);
    claw_memory_item_list_free(&list);
}

/* Missing primary falls back to a valid .old, but .bak is never auto-promoted. */
static void test_record_missing_primary_fallback(void)
{
    char old_path[256];
    char bak_path[256];
    char *actual;

    remove_record_sidecars();
    snprintf(old_path, sizeof(old_path), "%s.old", s_memory.records_path);
    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.records_path);
    write_text(old_path, LEGACY_RECORD_PROJECT);
    write_text(bak_path, LEGACY_RECORD_KEPT);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, LEGACY_RECORD_PROJECT) == 0);
    free(actual);

    remove_record_sidecars();
    write_text(bak_path, LEGACY_RECORD_KEPT);
    CHECK(claw_memory_records_prepare_for_read() == ESP_ERR_INVALID_STATE);
    CHECK(access(s_memory.records_path, F_OK) != 0);
}

/* Appending to an existing record file keeps it intact (failure rollback itself is not simulated). */
static void test_append_keeps_existing_records(void)
{
    char *actual;

    remove_record_sidecars();
    write_text(s_memory.records_path, LEGACY_RECORD_KEPT);
    CHECK(append_file_text(s_memory.records_path, LEGACY_RECORD_PROJECT) == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strlen(actual) == strlen(LEGACY_RECORD_KEPT) + strlen(LEGACY_RECORD_PROJECT));
    free(actual);
}

/* NULs followed by data cannot hide a damaged JSONL tail behind a valid first record. */
static void test_record_validation_rejects_embedded_nul_tail(void)
{
    static const char bytes[] =
        "{\"id\":\"one\",\"source\":\"test\",\"content\":\"saved\",\"tags\":\"\","
        "\"keywords\":\"\",\"created_at\":1,\"updated_at\":1,\"access_count\":0,"
        "\"deleted\":false,\"summary_ids\":[]}\n\0{\"id\":\"two\"";

    remove_record_sidecars();
    write_bytes(s_memory.records_path, bytes, sizeof(bytes) - 1);
    CHECK(claw_memory_records_prepare_for_read() == ESP_ERR_INVALID_STATE);
    CHECK(file_size_bytes(s_memory.records_path) == sizeof(bytes) - 1);
}

/* A zero-filled tail after the last complete line is a torn tail and is truncated. */
static void test_record_trailing_nul_tail_is_truncated(void)
{
    static const char partial[] = "{\"id\":\"two\",\"sou\0\0\0\0";
    static const char only_nuls[] = "\0\0\0\0";
    char bytes[512];
    size_t kept = strlen(LEGACY_RECORD_KEPT);
    char *actual;

    remove_record_sidecars();
    memcpy(bytes, LEGACY_RECORD_KEPT, kept);
    memcpy(bytes + kept, only_nuls, sizeof(only_nuls) - 1);
    write_bytes(s_memory.records_path, bytes, kept + sizeof(only_nuls) - 1);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
    actual = read_text(s_memory.records_path);
    CHECK(actual && strcmp(actual, LEGACY_RECORD_KEPT) == 0);
    CHECK(file_size_bytes(s_memory.records_path) == kept);
    free(actual);

    memcpy(bytes + kept, partial, sizeof(partial) - 1);
    write_bytes(s_memory.records_path, bytes, kept + sizeof(partial) - 1);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
    CHECK(file_size_bytes(s_memory.records_path) == kept);
}

/* The original V2 record schema remains valid without later optional fields. */
static void test_record_validation_accepts_legacy_schema(void)
{
    remove_record_sidecars();
    write_text(s_memory.records_path, LEGACY_RECORD_KEPT);
    CHECK(claw_memory_records_prepare_for_read() == ESP_OK);
}

/* A healthy index cannot hide damaged records; confirmed repair promotes a complete backup. */
static void test_storage_check_reports_and_repairs_degraded_records(void)
{
    char bak_path[256];
    char output[384];

    remove_index_sidecars();
    remove_record_sidecars();
    write_text(s_memory.index_path,
               "{\"version\":3,\"next_summary_id\":1,\"last_compact_digest_size\":0,"
               "\"summaries\":[],\"keyword_index\":{}}");
    write_text(s_memory.records_path, "{\"id\":\"x\"}\n");
    s_memory.initialized = 0;
    s_memory.storage_degraded = true;
    s_memory.storage_repair_required = true;
    CHECK(claw_memory_storage_check(false, output, sizeof(output)) == ESP_OK);
    CHECK(strstr(output, "Memory index: OK") != NULL);
    CHECK(strstr(output, "Memory records: damaged") != NULL);
    CHECK(strstr(output, "Restart the device to resume") == NULL);

    snprintf(bak_path, sizeof(bak_path), "%s.bak", s_memory.records_path);
    write_text(bak_path, LEGACY_RECORD_KEPT);
    CHECK(claw_memory_storage_check(true, output, sizeof(output)) == ESP_OK);
    CHECK(strstr(output, "Memory records recovered") != NULL);
    CHECK(strstr(output, "Restart the device to resume") != NULL);
    s_memory.storage_repair_required = false;
    CHECK(claw_memory_storage_check(true, output, sizeof(output)) == ESP_OK);
    CHECK(strstr(output, "Restart the device to resume") == NULL);
    CHECK(strstr(output, "free storage") != NULL);
    s_memory.storage_degraded = false;
    s_memory.storage_repair_required = false;
    s_memory.initialized = 1;
}

/* Stale .old with a committed target must not block later atomic writes. */
static void test_atomic_file_stale_old_does_not_block_write(void)
{
    char path[256];
    char old_path[300];
    char *actual;

    snprintf(path, sizeof(path), "%s.user", s_memory.index_path);
    snprintf(old_path, sizeof(old_path), "%s.old", path);
    write_text(path, "new");
    write_text(old_path, "prev");
    CHECK(write_file_atomic(path, "next") == ESP_ERR_INVALID_STATE);
    CHECK(claw_memory_recover_atomic_file(path) == ESP_OK);
    CHECK(access(old_path, F_OK) != 0);
    CHECK(write_file_atomic(path, "next") == ESP_OK);
    actual = read_text(path);
    CHECK(actual && strcmp(actual, "next") == 0);
    free(actual);
}

/* Missing target with .old must restore the last committed content, not defaults. */
static void test_atomic_file_missing_target_restores_old(void)
{
    char path[256];
    char old_path[300];
    char *actual;

    snprintf(path, sizeof(path), "%s.memory", s_memory.index_path);
    snprintf(old_path, sizeof(old_path), "%s.old", path);
    unlink(path);
    write_text(old_path, "committed");
    CHECK(claw_memory_recover_atomic_file(path) == ESP_OK);
    CHECK(ensure_file_with_default(path, "default") == ESP_OK);
    actual = read_text(path);
    CHECK(actual && strcmp(actual, "committed") == 0);
    free(actual);
    CHECK(access(old_path, F_OK) != 0);
}

int main(void)
{
    char dir[] = "/tmp/claw-memory-index-XXXXXX";

    CHECK(mkdtemp(dir) != NULL);
    snprintf(s_memory.index_path, sizeof(s_memory.index_path), "%s/index.json", dir);
    snprintf(s_memory.records_path, sizeof(s_memory.records_path), "%s/records.jsonl", dir);
    s_memory.initialized = 1;

    test_close_failure_preserves_index();
    test_promote_failure_restores_index();
    test_load_recovers_interrupted_replace();
    test_prepare_before_default_preserves_backup();
    test_load_falls_back_from_partial_tmp();
    test_load_rejects_incomplete_primary_index();
    test_load_promotion_failure_preserves_all_copies();
    test_index_validation_rejects_embedded_nul_tail();
    test_check_is_read_only();
    test_repair_rebuilds_index_from_complete_records();
    test_repair_rejects_incomplete_records();
    test_record_snapshot_close_failure_preserves_records();
    test_record_snapshot_serializes_large_record();
    test_record_snapshot_recovers_interrupted_replace();
    test_record_recovery_archives_malformed_primary();
    test_record_recovery_failure_preserves_all_copies();
    test_record_torn_tail_is_truncated();
    test_record_invalid_middle_line_is_skipped();
    test_record_missing_primary_fallback();
    test_append_keeps_existing_records();
    test_record_validation_rejects_embedded_nul_tail();
    test_record_trailing_nul_tail_is_truncated();
    test_record_validation_accepts_legacy_schema();
    test_storage_check_reports_and_repairs_degraded_records();
    test_atomic_file_stale_old_does_not_block_write();
    test_atomic_file_missing_target_restores_old();

    if (s_failures) {
        fprintf(stderr, "%d memory index recovery test(s) failed\n", s_failures);
        return 1;
    }
    puts("memory index recovery tests passed");
    return 0;
}
