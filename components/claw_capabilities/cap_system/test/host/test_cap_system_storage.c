#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>
#include <unistd.h>

#include "cap_system_storage.h"
#include "claw_paths.h"
#include "claw_storage_guard.h"

static int s_failed;
static char s_root[256];
static size_t s_allocation_unit;
static int s_check_calls;
static int s_repair_calls;
static const char *s_lstat_fail_suffix;
static int s_readdir_fail_after = -1;
static int s_readdir_calls;

#define CHECK(cond) do { if (!(cond)) { \
    printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); s_failed++; \
} } while (0)

int cap_system_storage_test_lstat(const char *path, struct stat *st)
{
    size_t path_len = strlen(path);
    size_t suffix_len = s_lstat_fail_suffix ? strlen(s_lstat_fail_suffix) : 0;

    if (suffix_len && suffix_len <= path_len &&
            strcmp(path + path_len - suffix_len, s_lstat_fail_suffix) == 0) {
        errno = EIO;
        return -1;
    }
    return lstat(path, st);
}

struct dirent *cap_system_storage_test_readdir(DIR *dir)
{
    if (s_readdir_fail_after >= 0 && s_readdir_calls++ >= s_readdir_fail_after) {
        errno = EIO;
        return NULL;
    }
    return readdir(dir);
}

int cap_system_storage_test_closedir(DIR *dir)
{
    return closedir(dir);
}

const char *esp_err_to_name(esp_err_t err)
{
    (void)err;
    return "host error";
}

const char *claw_paths_get(claw_path_root_t root)
{
    return root == CLAW_PATH_DATA ? s_root : NULL;
}

esp_err_t claw_paths_join(claw_path_root_t root, const char *subpath, char *out, size_t out_size)
{
    int n;

    if (root != CLAW_PATH_DATA || !out || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    n = snprintf(out, out_size, "%s%s%s", s_root, subpath && subpath[0] ? "/" : "",
                 subpath && subpath[0] ? subpath : "");
    return n >= 0 && (size_t)n < out_size ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

void claw_storage_set_allocation_unit(size_t bytes)
{
    s_allocation_unit = bytes;
}

size_t claw_storage_get_allocation_unit(void)
{
    return s_allocation_unit;
}

esp_err_t esp_vfs_fat_info(const char *base_path, uint64_t *total, uint64_t *free_bytes)
{
    struct statvfs st;

    if (statvfs(base_path, &st) != 0) {
        return ESP_FAIL;
    }
    *total = (uint64_t)st.f_blocks * st.f_frsize;
    *free_bytes = (uint64_t)st.f_bavail * st.f_frsize;
    return ESP_OK;
}

esp_err_t claw_memory_storage_check(bool repair, char *out, size_t out_size)
{
    s_check_calls++;
    s_repair_calls += repair ? 1 : 0;
    snprintf(out, out_size, "%s", repair ? "memory index repaired" : "memory index healthy");
    return ESP_OK;
}

static void make_dir(const char *relative)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", s_root, relative);
    CHECK(mkdir(path, 0700) == 0 || errno == EEXIST);
}

static void write_file(const char *relative, const char *content, time_t age_seconds)
{
    char path[512];
    FILE *file;

    snprintf(path, sizeof(path), "%s/%s", s_root, relative);
    file = fopen(path, "wb");
    CHECK(file != NULL);
    if (!file) {
        return;
    }
    CHECK(fwrite(content, 1, strlen(content), file) == strlen(content));
    CHECK(fclose(file) == 0);
    if (age_seconds > 0) {
        struct timespec times[2];
        times[0].tv_sec = times[1].tv_sec = time(NULL) - age_seconds;
        times[0].tv_nsec = times[1].tv_nsec = 0;
        CHECK(utimensat(AT_FDCWD, path, times, 0) == 0);
    }
}

static bool exists(const char *relative)
{
    char path[512];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s", s_root, relative);
    return stat(path, &st) == 0;
}

static claw_cap_call_context_t context(claw_cap_caller_t caller, const char *channel,
                                       const char *chat, const char *source)
{
    return (claw_cap_call_context_t) {
        .caller = caller,
        .channel = channel,
        .chat_id = chat,
        .source_cap = source,
    };
}

static esp_err_t command(const char *text, const claw_cap_call_context_t *ctx,
                         char *out, size_t out_size)
{
    char json[192];
    snprintf(json, sizeof(json), "{\"command\":\"%s\"}", text);
    return cap_system_storage_execute(json, ctx, out, out_size);
}

static bool read_token(const char *out, char *token, size_t token_size)
{
    const char *marker = "/storage confirm ";
    const char *start = strstr(out, marker);
    size_t len;

    if (!start) {
        return false;
    }
    start += strlen(marker);
    len = strcspn(start, " \r\n");
    if (len == 0 || len >= token_size) {
        return false;
    }
    memcpy(token, start, len);
    token[len] = '\0';
    return true;
}

static void test_status_reports_logical_and_allocated_usage(void)
{
    char out[4096];
    claw_cap_call_context_t console = context(CLAW_CAP_CALLER_CONSOLE, NULL, NULL, "console");

    write_file("sessions/live.log", "x", 0);
    cap_system_storage_set_allocation_unit(4096);
    CHECK(command("status", &console, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "sessions") != NULL);
    CHECK(strstr(out, "logical=1") != NULL);
    CHECK(strstr(out, "allocated=4096") != NULL);
    CHECK(strstr(out, "free=") != NULL);
}

static void test_safe_cleanup_is_bound_to_direct_telegram_chat_and_protects_paths(void)
{
    char out[4096];
    char token[64];
    char confirm[96];
    const time_t old = 2 * 24 * 60 * 60;
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");
    claw_cap_call_context_t wrong_chat = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "99", "tg_gateway");
    claw_cap_call_context_t console = context(CLAW_CAP_CALLER_CONSOLE, NULL, NULL, "console");
    claw_cap_call_context_t agent = context(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "42", "tg_gateway");
    claw_cap_call_context_t routed = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "claw_event_router");

    write_file("sessions/orphan.skills.json", "{}", old);
    write_file("sessions/paired.skills.json", "{}", old);
    write_file("sessions/paired.log", "turn", old);
    write_file("inbox/upload.tmp", "partial", old);
    write_file("inbox/keep.bak", "backup", old);
    write_file("skills/never.tmp", "user", old);

    CHECK(command("clean safe", &console, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "direct Telegram") != NULL);
    CHECK(command("clean safe", &agent, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "direct Telegram") != NULL);
    CHECK(command("clean safe", &routed, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "direct Telegram") != NULL);
    CHECK(command("clean ../../memory", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "/storage clean") != NULL);
    CHECK(strstr(out, "/storage confirm") == NULL);

    CHECK(command("clean safe", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "orphan.skills.json") != NULL);
    CHECK(strstr(out, "upload.tmp") != NULL);
    CHECK(strstr(out, "paired.skills.json") == NULL);
    CHECK(strstr(out, "keep.bak") == NULL);
    CHECK(strstr(out, "never.tmp") == NULL);
    CHECK(read_token(out, token, sizeof(token)));

    snprintf(confirm, sizeof(confirm), "confirm %s", token);
    CHECK(command(confirm, &wrong_chat, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "does not belong") != NULL);
    CHECK(exists("sessions/orphan.skills.json"));

    CHECK(command(confirm, &direct, out, sizeof(out)) == ESP_OK);
    CHECK(!exists("sessions/orphan.skills.json"));
    CHECK(!exists("inbox/upload.tmp"));
    CHECK(exists("sessions/paired.skills.json"));
    CHECK(exists("sessions/paired.log"));
    CHECK(exists("inbox/keep.bak"));
    CHECK(exists("skills/never.tmp"));
}

static void test_confirm_revalidates_changed_files(void)
{
    char out[4096];
    char token[64];
    char confirm[96];
    const time_t old = 2 * 24 * 60 * 60;
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");

    write_file("sessions/changed.skills.json", "{}", old);
    CHECK(command("clean safe", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(read_token(out, token, sizeof(token)));
    write_file("sessions/changed.skills.json", "changed", old);
    snprintf(confirm, sizeof(confirm), "confirm %s", token);
    CHECK(command(confirm, &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "changed=1") != NULL);
    CHECK(exists("sessions/changed.skills.json"));
}

static void test_attachments_require_explicit_selection_and_age_guard(void)
{
    char out[4096];
    const time_t old = 8 * 24 * 60 * 60;
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");

    write_file("inbox/old.ogg", "old voice", old);
    write_file("inbox/new.ogg", "new voice", 0);
    CHECK(command("preview safe", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "old.ogg") == NULL);
    CHECK(command("preview attachments", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "old.ogg") != NULL);
    CHECK(strstr(out, "new.ogg") == NULL);
}

static void test_memory_check_is_read_only_and_repair_needs_confirmation(void)
{
    char out[4096];
    char token[64];
    char confirm[96];
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");
    claw_cap_call_context_t console = context(CLAW_CAP_CALLER_CONSOLE, NULL, NULL, "console");

    s_check_calls = 0;
    s_repair_calls = 0;
    CHECK(command("check", &console, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "healthy") != NULL);
    CHECK(s_check_calls == 1 && s_repair_calls == 0);
    CHECK(command("repair", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(read_token(out, token, sizeof(token)));
    CHECK(s_repair_calls == 0);
    snprintf(confirm, sizeof(confirm), "confirm %s", token);
    CHECK(command(confirm, &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "repaired") != NULL);
    CHECK(s_repair_calls == 1);
}

static void test_incomplete_traversal_never_issues_a_token(void)
{
    char out[4096];
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");

    make_dir("inbox/a");
    make_dir("inbox/a/b");
    make_dir("inbox/a/b/c");
    make_dir("inbox/a/b/c/d");
    write_file("inbox/a/b/c/d/old.tmp", "partial", 2 * 24 * 60 * 60);
    CHECK(command("clean safe", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "incomplete") != NULL);
    CHECK(strstr(out, "/storage confirm") == NULL);
    CHECK(exists("inbox/a/b/c/d/old.tmp"));
}

static void test_sibling_lookup_error_never_masquerades_as_absent(void)
{
    char out[4096];
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");

    write_file("sessions/ioerror.skills.json", "{}", 2 * 24 * 60 * 60);
    s_lstat_fail_suffix = "ioerror.log";
    CHECK(command("clean safe", &direct, out, sizeof(out)) == ESP_OK);
    s_lstat_fail_suffix = NULL;
    CHECK(strstr(out, "incomplete") != NULL);
    CHECK(strstr(out, "/storage confirm") == NULL);
    CHECK(exists("sessions/ioerror.skills.json"));
}

static void test_directory_read_error_never_issues_a_token(void)
{
    char out[4096];
    claw_cap_call_context_t direct = context(CLAW_CAP_CALLER_SYSTEM, "telegram", "42", "tg_gateway");

    write_file("sessions/readdir.skills.json", "{}", 2 * 24 * 60 * 60);
    s_readdir_calls = 0;
    s_readdir_fail_after = 0;
    CHECK(command("clean safe", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "incomplete") != NULL);
    CHECK(strstr(out, "/storage confirm") == NULL);
    CHECK(exists("sessions/readdir.skills.json"));
    s_readdir_calls = 0;
    CHECK(command("status", &direct, out, sizeof(out)) == ESP_OK);
    CHECK(strstr(out, "(partial)") != NULL);
    s_readdir_fail_after = -1;
}

int main(void)
{
    char template[] = "/tmp/cap-system-storage-XXXXXX";

    CHECK(mkdtemp(template) != NULL);
    snprintf(s_root, sizeof(s_root), "%s", template);
    make_dir("sessions");
    make_dir("inbox");
    make_dir("memory");
    make_dir("skills");
    make_dir("apps");

    test_status_reports_logical_and_allocated_usage();
    test_safe_cleanup_is_bound_to_direct_telegram_chat_and_protects_paths();
    test_confirm_revalidates_changed_files();
    test_attachments_require_explicit_selection_and_age_guard();
    test_memory_check_is_read_only_and_repair_needs_confirmation();
    test_directory_read_error_never_issues_a_token();
    test_sibling_lookup_error_never_masquerades_as_absent();
    test_incomplete_traversal_never_issues_a_token();

    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all cap_system_storage tests passed\n");
    return 0;
}
