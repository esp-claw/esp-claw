/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Sandboxed WASM apps (WAMR fast interpreter) loaded from
 * <storage>/apps/<name>/{manifest.json,app.wasm,signature.json}.
 *
 * Threads: all WAMR calls run on one pthread ("wasm_apps", PSRAM stack; WAMR's ESP-IDF port calls
 * pthread_self()). Requesters (tool calls, /apps, boot) hand it a request, then act as its
 * watchdog: every entry into app code has a wall-clock budget, and when it runs out the requester
 * calls wasm_runtime_terminate(), which WAMR's thread manager turns into a stop at the next
 * branch/call. Time a host function spends blocked (HTTP, Telegram confirmation) is not counted.
 * A trapped or terminated instance is torn down and re-instantiated lazily on the next call;
 * after CAP_WASM_MAX_FAILURES consecutive failures the app is disabled until reload or reboot.
 *
 * On-demand loading: at boot every enabled app with a valid signature registers its tools from
 * <name>/tools.json (written after its last successful app_init, bound to the wasm hash) without
 * staying in memory. A call to an unloaded app loads it first. An app is unloaded after
 * CAP_WASM_IDLE_MS without calls, and the least recently used ones are unloaded when PSRAM would
 * drop below the reserve. Calls run one at a time on the WASM thread, which is also the only
 * place apps are unloaded, so an app with a call in progress is never evicted.
 *
 * Timers: an app with permissions.timer calls claw_timer_set(interval) (kept in NVS) and exports
 * on_timer(). The "wasm_timer" task wakes up every CAP_WASM_TIMER_TICK_MS and, when a timer is due,
 * submits a request like any other requester (and watches its budget); the WASM thread loads the
 * app if needed and calls on_timer() under limits.call_timeout_ms. Idle unload reclaims it as
 * usual. After CAP_WASM_TIMER_MAX_FAILURES consecutive failed runs the timer stops (until reload
 * or reboot) and the allowed Telegram users are told.
 *
 * Capability groups: "cap_wasm_apps" holds the app tools; it is unregistered and re-registered
 * when the tool set changes. "cap_wasm_apps_mgr" holds the management tools and the restricted
 * /apps command handler, which must not live in the group they re-register (app_capabilities.c
 * makes it LLM-visible together with cap_wasm_apps).
 */
#include "cap_wasm_apps.h"

#include <dirent.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "cJSON.h"
#include "cap_wasm_internal.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_pthread.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_GROUP            "cap_wasm_apps"
#define CAP_WASM_MGR_GROUP        "cap_wasm_apps_mgr"
#define CAP_WASM_MAX_TOOLS        32   /* dispatch slots, see CAP_WASM_SLOTS */
#define CAP_WASM_TOOLS_JSON_MAX   (CAP_WASM_MAX_TOOLS * 3 * 1024)
#define CAP_WASM_TOOL_DESC_MAX    256  /* claw_cap truncates longer tool descriptions */
#define CAP_WASM_TOOL_SCHEMA_MAX  2048
#define CAP_WASM_EXEC_STACK       (16 * 1024) /* WASM operand/frame stack */
#define CAP_WASM_TASK_STACK       (16 * 1024) /* native stack of the WASM thread, PSRAM */
#define CAP_WASM_INIT_MS          2000
#define CAP_WASM_MAX_FAILURES     3
#define CAP_WASM_PSRAM_RESERVE    (1024 * 1024)
#define CAP_WASM_LOAD_OVERHEAD    (32 * 1024)
#define CAP_WASM_WATCHDOG_TICK_MS 50
#define CAP_WASM_STATUS_WAIT_MS   3000
#define CAP_WASM_DRAIN_MS         10000
#define CAP_WASM_IDLE_MS          (10 * 60 * 1000)
#define CAP_WASM_SWEEP_MS         (30 * 1000)
#define CAP_WASM_TIMER_TICK_MS    (15 * 1000) /* timer resolution; intervals are >= 60 s */
#define CAP_WASM_TIMER_STACK      4096
#define CAP_WASM_TIMER_MAX_FAILURES 3
#define CAP_WASM_TIMER_PERSIST_S  3600 /* timers at least this long keep their last run across reboots */

typedef struct {
    cap_wasm_req_type_t type;
    int slot;                             /* CALL */
    const char *arg;                      /* CALL: input JSON; admin: app name; STATUS: "json" */
    const char *extra;                    /* INSTALL: source URL */
    const claw_cap_call_context_t *ctx;   /* CALL */
    char *output;
    size_t output_size;
    esp_err_t err;
} cap_wasm_req_t;

char g_cap_wasm_apps_dir[64];
EXT_RAM_BSS_ATTR cap_wasm_key_t g_cap_wasm_trusted[CAP_WASM_MAX_TRUSTED];
size_t g_cap_wasm_trusted_count;
static bool s_allow_unsigned;

/* Slots of removed apps have an empty name and are reused; s_app_count is the high-water mark. */
static EXT_RAM_BSS_ATTR cap_wasm_app_t s_apps[CAP_WASM_MAX_APPS];
static size_t s_app_count;
static EXT_RAM_BSS_ATTR cap_wasm_tool_t s_tools[CAP_WASM_MAX_TOOLS];
static size_t s_tool_count;
static EXT_RAM_BSS_ATTR claw_cap_descriptor_t s_descriptors[CAP_WASM_MAX_TOOLS];
static claw_cap_group_t s_group;
static bool s_runtime_ok;

static QueueHandle_t s_req_queue;
static SemaphoreHandle_t s_done;
static SemaphoreHandle_t s_call_lock;
static atomic_uint s_timer_next_s = UINT32_MAX; /* uptime when the next timer is due */

/* The app code currently running on the WASM thread, watched by the requester. */
static struct {
    SemaphoreHandle_t lock;
    wasm_module_inst_t inst;
    int64_t deadline_us;
    int64_t paused_at_us;
    bool terminated;
} s_exec;

static void cap_wasm_timer_restore(cap_wasm_app_t *app);

/* ---------- PSRAM allocator for the WAMR runtime and linear memory ---------- */

static void *cap_wasm_malloc(unsigned int size)
{
    return heap_caps_malloc(size, CAP_WASM_PSRAM_CAPS);
}

static void *cap_wasm_realloc(void *ptr, unsigned int size)
{
    return heap_caps_realloc(ptr, size, CAP_WASM_PSRAM_CAPS);
}

static void cap_wasm_free(void *ptr)
{
    heap_caps_free(ptr);
}

/* ---------- Call budget ---------- */

static void cap_wasm_budget_begin(cap_wasm_app_t *app, uint32_t budget_ms)
{
    xSemaphoreTake(s_exec.lock, portMAX_DELAY);
    s_exec.inst = app->inst;
    s_exec.deadline_us = esp_timer_get_time() + (int64_t)budget_ms * 1000;
    s_exec.paused_at_us = 0;
    s_exec.terminated = false;
    xSemaphoreGive(s_exec.lock);
}

/* Returns true when the watchdog terminated the execution. */
static bool cap_wasm_budget_end(void)
{
    bool terminated;

    xSemaphoreTake(s_exec.lock, portMAX_DELAY);
    terminated = s_exec.terminated;
    s_exec.inst = NULL;
    xSemaphoreGive(s_exec.lock);
    return terminated;
}

void cap_wasm_budget_pause(bool pause)
{
    int64_t now = esp_timer_get_time();

    xSemaphoreTake(s_exec.lock, portMAX_DELAY);
    if (pause) {
        s_exec.paused_at_us = now;
    } else if (s_exec.paused_at_us) {
        s_exec.deadline_us += now - s_exec.paused_at_us;
        s_exec.paused_at_us = 0;
    }
    xSemaphoreGive(s_exec.lock);
}

/* Runs on the requester while it waits. Terminating under s_exec.lock guarantees the WASM thread
 * cannot tear the instance down concurrently (it takes the lock in cap_wasm_budget_end first). */
static void cap_wasm_watchdog(void)
{
    xSemaphoreTake(s_exec.lock, portMAX_DELAY);
    if (s_exec.inst && !s_exec.terminated && !s_exec.paused_at_us &&
            esp_timer_get_time() > s_exec.deadline_us) {
        wasm_runtime_terminate(s_exec.inst);
        s_exec.terminated = true;
    }
    xSemaphoreGive(s_exec.lock);
}

/* ---------- Files ---------- */

char *cap_wasm_read_file(const char *path, size_t max_size, size_t *out_size)
{
    struct stat st;
    FILE *f = NULL;
    char *buf = NULL;

    if (stat(path, &st) != 0 || st.st_size <= 0 || (size_t)st.st_size > max_size) {
        return NULL;
    }
    buf = heap_caps_malloc(st.st_size + 1, CAP_WASM_PSRAM_CAPS);
    f = buf ? fopen(path, "rb") : NULL;
    if (!f || fread(buf, 1, st.st_size, f) != (size_t)st.st_size) {
        heap_caps_free(buf);
        buf = NULL;
    } else {
        buf[st.st_size] = '\0';
        *out_size = (size_t)st.st_size;
    }
    if (f) {
        fclose(f);
    }
    return buf;
}

bool cap_wasm_write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(data, 1, len, f) == len;

    if (f && fclose(f) != 0) {
        ok = false;
    }
    if (!ok) {
        unlink(path);
    }
    return ok;
}

/* Writes via a temp file. FAT cannot rename over an existing file, so the old one is moved aside
 * first and restored if the final rename fails (as http_server_replace_file() does). */
static bool cap_wasm_write_file_atomic(const char *path, const char *data)
{
    char tmp[128];
    char bak[128];

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    snprintf(bak, sizeof(bak), "%s.bak", path);
    if (!cap_wasm_write_file(tmp, data, strlen(data))) {
        return false;
    }
    unlink(bak);
    if (access(path, F_OK) == 0 && rename(path, bak) != 0) {
        unlink(tmp);
        return false;
    }
    if (rename(tmp, path) != 0) {
        rename(bak, path);
        unlink(tmp);
        return false;
    }
    unlink(bak);
    return true;
}

bool cap_wasm_rmdir(const char *path)
{
    DIR *dir = opendir(path);
    struct dirent *ent;
    char child[sizeof(g_cap_wasm_apps_dir) + 2 * sizeof(ent->d_name)];

    if (!dir) {
        return access(path, F_OK) != 0;
    }
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
            snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            unlink(child);
        }
    }
    closedir(dir);
    return rmdir(path) == 0;
}

static void cap_wasm_app_path(const cap_wasm_app_t *app, const char *file, char *out, size_t size)
{
    snprintf(out, size, "%s/%s/%s", g_cap_wasm_apps_dir, app->name, file);
}

/* ---------- Tools ---------- */

static cap_wasm_tool_t *cap_wasm_find_tool(const char *name)
{
    for (size_t i = 0; i < s_tool_count; i++) {
        if (strcmp(s_tools[i].name, name) == 0) {
            return &s_tools[i];
        }
    }
    return NULL;
}

static size_t cap_wasm_app_tool_count(const cap_wasm_app_t *app)
{
    size_t count = 0;

    for (size_t i = 0; i < s_tool_count; i++) {
        count += s_tools[i].app == app;
    }
    return count;
}

static void cap_wasm_remove_tools(const cap_wasm_app_t *app)
{
    size_t kept = 0;

    for (size_t i = 0; i < s_tool_count; i++) {
        if (s_tools[i].app == app) {
            heap_caps_free(s_tools[i].name);
            heap_caps_free(s_tools[i].desc);
            heap_caps_free(s_tools[i].schema);
        } else {
            s_tools[kept++] = s_tools[i];
        }
    }
    memset(&s_tools[kept], 0, (s_tool_count - kept) * sizeof(s_tools[0]));
    s_tool_count = kept;
}

static char *cap_wasm_dup(const char *src, size_t len)
{
    char *dst = heap_caps_malloc(len + 1, CAP_WASM_PSRAM_CAPS);

    if (dst) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

int32_t cap_wasm_tool_add(cap_wasm_app_t *app, const char *name, uint32_t name_len,
                          const char *desc, uint32_t desc_len, const char *schema, uint32_t schema_len)
{
    char full[CAP_WASM_TOOL_NAME_MAX + 1];
    size_t prefix = strlen(app->name) + 1;
    cap_wasm_tool_t *tool;
    cJSON *parsed;

    if (prefix + name_len > CAP_WASM_TOOL_NAME_MAX) {
        ESP_LOGW(TAG, "[%s] tool name too long (max %d chars incl. app prefix)", app->name, CAP_WASM_TOOL_NAME_MAX);
        return -CAP_WASM_EINVAL;
    }
    snprintf(full, sizeof(full), "%s_%.*s", app->name, (int)name_len, name);
    if (!cap_wasm_name_valid(full, strlen(full), CAP_WASM_TOOL_NAME_MAX) || name_len == 0 ||
            strlen(full) != prefix + name_len) {
        ESP_LOGW(TAG, "[%s] invalid tool name '%s' (use [a-z0-9_])", app->name, full);
        return -CAP_WASM_EINVAL;
    }
    tool = cap_wasm_find_tool(full);
    if (app->tools_frozen) {
        /* Tools come from tools.json or an earlier app_init: the registered set must not change. */
        if (tool && tool->app == app) {
            app->init_tools++;
            return tool->local_idx;
        }
        app->tools_changed = true;
        return -CAP_WASM_EPERM;
    }
    if (tool || claw_cap_find(full)) {
        ESP_LOGW(TAG, "[%s] tool '%s' collides with an existing tool", app->name, full);
        return -CAP_WASM_EEXIST;
    }
    if (desc_len > CAP_WASM_TOOL_DESC_MAX || schema_len > CAP_WASM_TOOL_SCHEMA_MAX) {
        ESP_LOGW(TAG, "[%s] tool '%s': description max %d, schema max %d bytes", app->name, full,
                 CAP_WASM_TOOL_DESC_MAX, CAP_WASM_TOOL_SCHEMA_MAX);
        return -CAP_WASM_E2BIG;
    }
    if (s_tool_count >= CAP_WASM_MAX_TOOLS) {
        ESP_LOGW(TAG, "[%s] tool '%s': all %d WASM tool slots are used", app->name, full, CAP_WASM_MAX_TOOLS);
        return -CAP_WASM_ENOSPC;
    }
    tool = &s_tools[s_tool_count];
    tool->name = cap_wasm_dup(full, strlen(full));
    tool->desc = cap_wasm_dup(desc, desc_len);
    tool->schema = cap_wasm_dup(schema, schema_len);
    if (!tool->name || !tool->desc || !tool->schema) {
        heap_caps_free(tool->name);
        heap_caps_free(tool->desc);
        heap_caps_free(tool->schema);
        memset(tool, 0, sizeof(*tool));
        return -CAP_WASM_ENOMEM;
    }
    cap_wasm_utf8_sanitize(tool->desc, desc_len);
    cap_wasm_utf8_sanitize(tool->schema, schema_len);
    parsed = cJSON_Parse(tool->schema);
    if (!cJSON_IsObject(parsed)) {
        ESP_LOGW(TAG, "[%s] tool '%s': schema is not a JSON object", app->name, full);
        heap_caps_free(tool->name);
        heap_caps_free(tool->desc);
        heap_caps_free(tool->schema);
        memset(tool, 0, sizeof(*tool));
        cJSON_Delete(parsed);
        return -CAP_WASM_EINVAL;
    }
    cJSON_Delete(parsed);
    tool->app = app;
    tool->local_idx = (int32_t)cap_wasm_app_tool_count(app);
    s_tool_count++;
    return tool->local_idx;
}

/* Registers the tools cached in tools.json if it belongs to the current app.wasm. */
static bool cap_wasm_tools_from_cache(cap_wasm_app_t *app)
{
    char path[128];
    size_t size = 0;
    char *json;
    cJSON *root;
    const cJSON *tool = NULL;
    const char *sha;
    bool ok;

    cap_wasm_app_path(app, "tools.json", path, sizeof(path));
    json = cap_wasm_read_file(path, CAP_WASM_TOOLS_JSON_MAX, &size);
    root = json ? cJSON_Parse(json) : NULL;
    heap_caps_free(json);
    sha = cJSON_GetStringValue(cJSON_GetObjectItem(root, "wasm_sha256"));
    ok = cJSON_IsArray(cJSON_GetObjectItem(root, "tools")) && sha && strcmp(sha, app->wasm_sha256) == 0;
    cJSON_ArrayForEach(tool, (ok ? cJSON_GetObjectItem(root, "tools") : NULL)) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(tool, "name"));
        const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(tool, "description"));
        const char *schema = cJSON_GetStringValue(cJSON_GetObjectItem(tool, "schema"));

        if (!name || !desc || !schema ||
                cap_wasm_tool_add(app, name, strlen(name), desc, strlen(desc), schema, strlen(schema)) < 0) {
            ok = false;
            break;
        }
    }
    cJSON_Delete(root);
    if (!ok) {
        cap_wasm_remove_tools(app);
    }
    return ok;
}

static void cap_wasm_tools_to_cache(const cap_wasm_app_t *app)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *tools = cJSON_AddArrayToObject(root, "tools");
    size_t prefix = strlen(app->name) + 1;
    char path[128];
    char *json;

    cJSON_AddStringToObject(root, "wasm_sha256", app->wasm_sha256);
    for (size_t i = 0; i < s_tool_count; i++) {
        if (s_tools[i].app == app) {
            cJSON *tool = cJSON_CreateObject();

            cJSON_AddStringToObject(tool, "name", s_tools[i].name + prefix);
            cJSON_AddStringToObject(tool, "description", s_tools[i].desc);
            cJSON_AddStringToObject(tool, "schema", s_tools[i].schema);
            cJSON_AddItemToArray(tools, tool);
        }
    }
    json = cJSON_PrintUnformatted(root);
    cap_wasm_app_path(app, "tools.json", path, sizeof(path));
    if (!json || !cap_wasm_write_file_atomic(path, json)) {
        ESP_LOGW(TAG, "[%s] cannot write tools.json; the app is loaded at every boot", app->name);
    }
    free(json);
    cJSON_Delete(root);
}

/* ---------- Instance lifecycle (WASM thread) ---------- */

static void cap_wasm_set_error(cap_wasm_app_t *app, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void cap_wasm_set_error(cap_wasm_app_t *app, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(app->last_error, sizeof(app->last_error), fmt, ap);
    va_end(ap);
    ESP_LOGE(TAG, "[%s] %s", app->name, app->last_error);
}

static void cap_wasm_teardown(cap_wasm_app_t *app)
{
    if (app->env) {
        wasm_runtime_destroy_exec_env(app->env);
    }
    if (app->inst) {
        wasm_runtime_deinstantiate(app->inst);
    }
    app->env = NULL;
    app->inst = NULL;
    app->fn_alloc = NULL;
    app->fn_call = NULL;
    app->fn_timer = NULL;
}

/* Frees the module and instance; registered tools stay. */
static void cap_wasm_unload(cap_wasm_app_t *app)
{
    cap_wasm_teardown(app);
    if (app->module) {
        wasm_runtime_unload(app->module);
        app->module = NULL;
    }
    if (app->state == CAP_WASM_APP_LOADED) {
        app->state = CAP_WASM_APP_UNLOADED;
    }
    app->psram_bytes = 0;
}

/* Instantiates the loaded module and runs app_init(). */
static bool cap_wasm_instantiate(cap_wasm_app_t *app)
{
    InstantiationArgs args = {
        .default_stack_size = CAP_WASM_EXEC_STACK,
        .host_managed_heap_size = 0,
        .max_memory_pages = app->mf.memory_kb / 64,
    };
    wasm_function_inst_t fn_init;
    wasm_memory_inst_t mem;
    char err[128];
    bool terminated;
    bool ok;

    app->inst = wasm_runtime_instantiate_ex(app->module, &args, err, sizeof(err));
    if (!app->inst) {
        cap_wasm_set_error(app, "instantiate failed: %s", err);
        return false;
    }
    mem = wasm_runtime_get_default_memory(app->inst);
    if (mem && wasm_memory_get_cur_page_count(mem) > args.max_memory_pages) {
        cap_wasm_set_error(app, "initial memory %" PRIu64 " KB exceeds limits.memory_kb %" PRIu32,
                           wasm_memory_get_cur_page_count(mem) * 64, app->mf.memory_kb);
        cap_wasm_teardown(app);
        return false;
    }
    wasm_runtime_set_custom_data(app->inst, app);
    app->env = wasm_runtime_create_exec_env(app->inst, CAP_WASM_EXEC_STACK);
    app->fn_alloc = wasm_runtime_lookup_function(app->inst, "app_alloc");
    app->fn_call = wasm_runtime_lookup_function(app->inst, "tool_call");
    app->fn_timer = wasm_runtime_lookup_function(app->inst, "on_timer");
    fn_init = wasm_runtime_lookup_function(app->inst, "app_init");
    if (!app->env || !app->fn_alloc || !app->fn_call || !fn_init) {
        cap_wasm_set_error(app, "%s", app->env ? "missing export app_init, app_alloc or tool_call" :
                           "cannot create exec env");
        cap_wasm_teardown(app);
        return false;
    }
    if ((app->mf.perms & CAP_WASM_PERM_TIMER) &&
            (!app->fn_timer || wasm_func_get_param_count(app->fn_timer, app->inst) != 0 ||
             wasm_func_get_result_count(app->fn_timer, app->inst) != 0)) {
        cap_wasm_set_error(app, "permissions.timer needs the export void on_timer(void)");
        cap_wasm_teardown(app);
        return false;
    }

    app->initializing = true;
    app->init_tools = 0;
    cap_wasm_budget_begin(app, CAP_WASM_INIT_MS);
    ok = wasm_runtime_call_wasm(app->env, fn_init, 0, NULL);
    terminated = cap_wasm_budget_end();
    app->initializing = false;
    if (!ok || terminated) {
        if (terminated) {
            cap_wasm_set_error(app, "app_init exceeded %d ms", CAP_WASM_INIT_MS);
        } else {
            cap_wasm_set_error(app, "app_init trapped: %s", wasm_runtime_get_exception(app->inst));
        }
        cap_wasm_teardown(app);
        return false;
    }
    if (app->tools_frozen && app->init_tools != cap_wasm_app_tool_count(app)) {
        app->tools_changed = true;
    }
    if (app->tools_changed) {
        ESP_LOGW(TAG, "[%s] app_init registered a different tool set than cached; refreshing", app->name);
    }
    app->state = CAP_WASM_APP_LOADED;
    return true;
}

static bool cap_wasm_check_imports(cap_wasm_app_t *app)
{
    int32_t count = wasm_runtime_get_import_count(app->module);

    for (int32_t i = 0; i < count; i++) {
        wasm_import_t imp;
        uint32_t perm = 0;
        uint16_t api = 0;

        wasm_runtime_get_import_type(app->module, i, &imp);
        if (imp.kind != WASM_IMPORT_EXPORT_KIND_FUNC || strcmp(imp.module_name, "claw") != 0 ||
                !cap_wasm_host_import_perm(imp.name, &perm, &api)) {
            cap_wasm_set_error(app, "imports unknown symbol %s.%s (only claw.* host functions exist)",
                               imp.module_name, imp.name);
            return false;
        }
        if (api > app->mf.api) {
            cap_wasm_set_error(app, "imports claw.%s, which needs api %u, but the manifest declares api %u", imp.name,
                               (unsigned)api, (unsigned)app->mf.api);
            return false;
        }
        if ((app->mf.perms & perm) != perm) {
            cap_wasm_set_error(app, "imports claw.%s but the manifest does not grant that permission", imp.name);
            return false;
        }
        if (!imp.linked) {
            cap_wasm_set_error(app, "claw.%s has the wrong signature (rebuild with the current esp-claw/app-sdk)", imp.name);
            return false;
        }
    }
    return true;
}

/*
 * Reads and validates manifest.json, reads app.wasm and checks signature.json. Returns app.wasm
 * (caller frees) or NULL with the state set to FAILED or UNSIGNED and last_error saying why.
 */
static char *cap_wasm_read_verified(cap_wasm_app_t *app, size_t *wasm_size)
{
    char path[128];
    char err[128];
    char *manifest = NULL;
    char *wasm = NULL;
    char *sig = NULL;
    size_t manifest_size = 0;
    size_t sig_size = 0;

    app->state = CAP_WASM_APP_FAILED;
    cap_wasm_app_path(app, "manifest.json", path, sizeof(path));
    manifest = cap_wasm_read_file(path, CAP_WASM_MANIFEST_MAX, &manifest_size);
    if (!manifest) {
        cap_wasm_set_error(app, "manifest.json missing or larger than %d bytes", CAP_WASM_MANIFEST_MAX);
        return NULL;
    }
    if (!cap_wasm_manifest_parse(manifest, app->name, &app->mf, err, sizeof(err)) ||
            !cap_wasm_api_check(&app->mf, err, sizeof(err))) {
        cap_wasm_set_error(app, "manifest.json: %s", err);
        goto done;
    }
    cap_wasm_nvs_namespace(app->name, app->nvs_ns);
    cap_wasm_app_path(app, "app.wasm", path, sizeof(path));
    wasm = cap_wasm_read_file(path, CAP_WASM_WASM_MAX, wasm_size);
    if (!wasm) {
        cap_wasm_set_error(app, "app.wasm missing or larger than %d KB", CAP_WASM_WASM_MAX / 1024);
        goto done;
    }
    cap_wasm_sha256_hex((const uint8_t *)wasm, *wasm_size, app->wasm_sha256);
    cap_wasm_app_path(app, "signature.json", path, sizeof(path));
    sig = cap_wasm_read_file(path, CAP_WASM_SIGNATURE_MAX, &sig_size);
    snprintf(err, sizeof(err), "no signature.json");
    if (sig && cap_wasm_sig_verify(sig, &app->mf, (const uint8_t *)manifest, manifest_size,
                                   (const uint8_t *)wasm, *wasm_size, g_cap_wasm_trusted,
                                   g_cap_wasm_trusted_count, 0, app->key_id, err, sizeof(err))) {
        goto done;
    }
    app->key_id[0] = '\0';
    if (s_allow_unsigned) {
        ESP_LOGW(TAG, "[%s] loading without a valid signature (%s): app_allow_unsigned is on", app->name, err);
        goto done;
    }
    app->state = CAP_WASM_APP_UNSIGNED;
    cap_wasm_set_error(app, "not loaded: %s (install signed packages with /app install)", err);
    heap_caps_free(wasm);
    wasm = NULL;

done:
    heap_caps_free(manifest);
    heap_caps_free(sig);
    return wasm;
}

/* Unloads least recently used apps until `need` bytes fit above the PSRAM reserve. */
static bool cap_wasm_make_room(const cap_wasm_app_t *app, size_t need)
{
    while (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < CAP_WASM_PSRAM_RESERVE + need) {
        int64_t last_used[CAP_WASM_MAX_APPS];
        bool loaded[CAP_WASM_MAX_APPS];
        int victim;

        for (size_t i = 0; i < s_app_count; i++) {
            last_used[i] = s_apps[i].last_used_us;
            loaded[i] = s_apps[i].module != NULL;
        }
        victim = cap_wasm_lru_pick(last_used, loaded, s_app_count, (int)(app - s_apps));
        if (victim < 0) {
            return false;
        }
        ESP_LOGI(TAG, "[%s] unloaded (least recently used) to make room for %s", s_apps[victim].name, app->name);
        cap_wasm_unload(&s_apps[victim]);
    }
    return true;
}

/*
 * Verifies, loads and instantiates one app. `frozen`: its tools are registered already and app_init
 * must name the same ones; otherwise they are registered now and cached in tools.json. `boot`
 * guards the load with a crash marker. On failure the app stays UNLOADED when frozen (the next
 * call retries) and is FAILED or UNSIGNED otherwise.
 */
static bool cap_wasm_load(cap_wasm_app_t *app, bool frozen, bool boot)
{
    char marker[128];
    char err[128];
    char *wasm;
    size_t size = 0;
    size_t psram_before;
    size_t internal_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    int64_t t0 = esp_timer_get_time();
    int64_t t_load;
    FILE *m;
    LoadArgs load_args = {
        .name = app->name,
        .wasm_binary_freeable = true,
    };

    app->failures = 0;
    app->last_error[0] = '\0';
    wasm = cap_wasm_read_verified(app, &size);
    if (!wasm) {
        goto failed;
    }
    /* Module + instance need roughly twice the binary plus the linear memory and stacks. */
    if (!cap_wasm_make_room(app, 2 * size + app->mf.memory_kb * 1024 + 2 * CAP_WASM_EXEC_STACK +
                            CAP_WASM_LOAD_OVERHEAD)) {
        cap_wasm_set_error(app, "not enough PSRAM (%u KB free, %u KB must stay free)",
                           (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
                           CAP_WASM_PSRAM_RESERVE / 1024);
        heap_caps_free(wasm);
        goto failed;
    }

    psram_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    cap_wasm_app_path(app, ".loading", marker, sizeof(marker));
    if (boot && (m = fopen(marker, "w")) != NULL) {
        fclose(m);
    }
    app->wasm_size = (uint32_t)size;
    app->tools_frozen = frozen;
    app->tools_changed = false;
    app->module = wasm_runtime_load_ex((uint8_t *)wasm, (uint32_t)size, &load_args, err, sizeof(err));
    heap_caps_free(wasm);
    t_load = esp_timer_get_time();
    if (!app->module) {
        cap_wasm_set_error(app, "load failed: %s", err);
    } else if (!cap_wasm_check_imports(app) || !cap_wasm_instantiate(app)) {
        cap_wasm_unload(app);
    }
    app->tools_frozen = false;
    if (boot) {
        unlink(marker);
    }
    if (!app->module) {
        if (!frozen) {
            cap_wasm_remove_tools(app);
        }
        goto failed;
    }

    app->psram_bytes = (uint32_t)(psram_before - heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    app->load_ms = (uint32_t)((esp_timer_get_time() - t0) / 1000);
    app->last_used_us = esp_timer_get_time();
    ESP_LOGI(TAG, "[%s] v%s loaded%s in %" PRIu32 " ms (load %" PRId64 " ms, init %" PRId64 " ms): %" PRIu32
             " B wasm, %u tools, mem cap %" PRIu32 " KB, psram -%" PRIu32 " B (free %u), internal -%d B",
             app->name, app->mf.version, frozen ? " on demand" : "", app->load_ms, (t_load - t0) / 1000,
             (esp_timer_get_time() - t_load) / 1000, app->wasm_size, (unsigned)cap_wasm_app_tool_count(app),
             app->mf.memory_kb, app->psram_bytes, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
             (int)(internal_before - heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
    if (!frozen) {
        cap_wasm_tools_to_cache(app);
    }
    return true;

failed:
    if (frozen && app->state != CAP_WASM_APP_UNSIGNED) {
        app->state = CAP_WASM_APP_UNLOADED;
    }
    return false;
}

/* Registers an enabled app's tools (from tools.json, else by loading it once) and leaves it unloaded. */
static void cap_wasm_probe(cap_wasm_app_t *app, bool boot)
{
    char marker[128];
    char *wasm;
    size_t size = 0;

    if (!app->enabled) {
        app->state = CAP_WASM_APP_DISABLED;
        snprintf(app->last_error, sizeof(app->last_error), "disabled; /apps enable %s turns it on", app->name);
        return;
    }
    cap_wasm_app_path(app, ".loading", marker, sizeof(marker));
    if (boot && access(marker, F_OK) == 0) {
        app->state = CAP_WASM_APP_FAILED;
        cap_wasm_set_error(app, "did not finish loading on a previous boot; /apps reload %s retries", app->name);
        return;
    }
    wasm = cap_wasm_read_verified(app, &size);
    if (!wasm) {
        return;
    }
    heap_caps_free(wasm);
    if (cap_wasm_tools_from_cache(app)) {
        app->state = CAP_WASM_APP_UNLOADED;
    } else if (cap_wasm_load(app, false, boot)) {
        cap_wasm_unload(app);
    }
    cap_wasm_timer_restore(app);
}

/* Loads an unloaded app for a call or apps_load. */
static bool cap_wasm_ensure_loaded(cap_wasm_app_t *app)
{
    return app->module || (app->state == CAP_WASM_APP_UNLOADED && cap_wasm_load(app, true, false));
}

static const char *cap_wasm_state_name(cap_wasm_app_state_t state)
{
    switch (state) {
    case CAP_WASM_APP_LOADED:
        return "loaded";
    case CAP_WASM_APP_UNLOADED:
        return "unloaded";
    case CAP_WASM_APP_DISABLED:
        return "disabled";
    case CAP_WASM_APP_UNSIGNED:
        return "unsigned";
    default:
        return "failed";
    }
}

static void cap_wasm_refresh_task(void *arg)
{
    char out[160];

    cap_wasm_admin(CAP_WASM_REQ_RELOAD, arg, NULL, out, sizeof(out));
    ESP_LOGI(TAG, "tool refresh: %s", out);
    free(arg);
    vTaskDeleteWithCaps(NULL);
}

/* A frozen app_init registered other tools: reload it non-frozen once the current call is done
 * (re-registering the group drains it, which cannot happen from inside one of its calls). */
static void cap_wasm_schedule_refresh(cap_wasm_app_t *app)
{
    char *name = strdup(app->name);

    app->tools_changed = false;
    if (!name || xTaskCreateWithCaps(cap_wasm_refresh_task, "wasm_refresh", 6144, name, 5, NULL,
                                     CAP_WASM_PSRAM_CAPS) != pdPASS) {
        free(name);
        ESP_LOGW(TAG, "[%s] cannot schedule the tool refresh; /apps reload %s does it", app->name, app->name);
    }
}

/* Runs one tool: copies the arguments into app memory, calls tool_call() under the budget. */
static void cap_wasm_do_call(cap_wasm_req_t *req)
{
    cap_wasm_tool_t *tool = &s_tools[req->slot];
    cap_wasm_app_t *app = tool->app;
    cap_wasm_call_t *call = &g_cap_wasm_call;
    uint32_t len = (uint32_t)strlen(req->arg);
    uint32_t argv[3] = { len + 1 };
    bool ok = false;
    bool terminated;
    int32_t rc = 0;

    req->err = ESP_FAIL;
    if (!cap_wasm_ensure_loaded(app)) {
        snprintf(req->output, req->output_size, "Error: WASM app '%s' is %s: %s", app->name,
                 cap_wasm_state_name(app->state), app->last_error[0] ? app->last_error : "see /apps");
        req->err = ESP_ERR_INVALID_STATE;
        return;
    }
    if (!app->inst) {
        app->tools_frozen = true;
        ok = cap_wasm_instantiate(app);
        app->tools_frozen = false;
        if (!ok) {
            snprintf(req->output, req->output_size, "Error: WASM app '%s' failed to restart: %s",
                     app->name, app->last_error);
            goto failure;
        }
    }

    *call = (cap_wasm_call_t) {
        .app = app,
        .ctx = req->ctx,
        .output = req->output,
        .output_size = req->output_size,
    };
    req->output[0] = '\0';
    app->calls++;
    cap_wasm_budget_begin(app, app->mf.call_timeout_ms);
    ok = wasm_runtime_call_wasm(app->env, app->fn_alloc, 1, argv);
    if (ok && (argv[0] == 0 || !wasm_runtime_validate_app_addr(app->inst, argv[0], len + 1))) {
        wasm_runtime_set_exception(app->inst, "app_alloc returned an invalid buffer");
        ok = false;
    }
    if (ok) {
        memcpy(wasm_runtime_addr_app_to_native(app->inst, argv[0]), req->arg, len + 1);
        argv[2] = len;
        argv[1] = argv[0];
        argv[0] = (uint32_t)tool->local_idx;
        ok = wasm_runtime_call_wasm(app->env, app->fn_call, 3, argv);
        rc = (int32_t)argv[0];
    }
    terminated = cap_wasm_budget_end();
    heap_caps_free(call->resp);
    *call = (cap_wasm_call_t) {0};
    app->last_used_us = esp_timer_get_time();

    if (!ok) {
        if (terminated) {
            snprintf(req->output, req->output_size, "Error: %s exceeded its %" PRIu32 " ms budget and was stopped",
                     tool->name, app->mf.call_timeout_ms);
        } else {
            snprintf(req->output, req->output_size, "Error: WASM app '%s' trapped in %s: %s",
                     app->name, tool->name, wasm_runtime_get_exception(app->inst));
        }
        snprintf(app->last_error, sizeof(app->last_error), "%s", req->output + strlen("Error: "));
        goto failure;
    }
    if (terminated) {
        /* Finished just as the budget ran out: the result stands, but the instance carries a
         * pending terminate flag and must be recreated. */
        cap_wasm_teardown(app);
    }
    app->failures = 0;
    if (rc != 0) {
        if (!req->output[0]) {
            snprintf(req->output, req->output_size, "Error: %s returned %" PRId32, tool->name, rc);
        }
    } else if (!req->output[0]) {
        snprintf(req->output, req->output_size, "Error: %s produced no result", tool->name);
    } else {
        req->err = ESP_OK;
    }
    goto done;

failure:
    cap_wasm_teardown(app);
    if (++app->failures >= CAP_WASM_MAX_FAILURES) {
        cap_wasm_unload(app);
        app->state = CAP_WASM_APP_DISABLED;
        ESP_LOGE(TAG, "[%s] disabled after %d consecutive failures (last: %s); /apps reload %s re-enables it",
                 app->name, CAP_WASM_MAX_FAILURES, app->last_error, app->name);
    } else {
        ESP_LOGW(TAG, "[%s] failure %u/%d: %s", app->name, app->failures, CAP_WASM_MAX_FAILURES, app->last_error);
    }

done:
    if (app->tools_changed) {
        cap_wasm_schedule_refresh(app);
    }
}

/* Unloads apps without calls for CAP_WASM_IDLE_MS. */
static void cap_wasm_idle_sweep(void)
{
    int64_t now = esp_timer_get_time();

    for (size_t i = 0; i < s_app_count; i++) {
        if (s_apps[i].module && now - s_apps[i].last_used_us > (int64_t)CAP_WASM_IDLE_MS * 1000) {
            ESP_LOGI(TAG, "[%s] unloaded after %d min without calls", s_apps[i].name, CAP_WASM_IDLE_MS / 60000);
            cap_wasm_unload(&s_apps[i]);
        }
    }
}

/* ---------- Timers (WASM thread; the wasm_timer task only wakes it) ---------- */

static uint32_t cap_wasm_uptime_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

/* True once SNTP (or the RTC) set the wall clock. */
static bool cap_wasm_clock_set(void)
{
    return time(NULL) > 1700000000;
}

static bool cap_wasm_timer_active(const cap_wasm_app_t *app)
{
    return app->name[0] && app->timer_s && !app->timer_off && app->enabled &&
           (app->state == CAP_WASM_APP_LOADED || app->state == CAP_WASM_APP_UNLOADED);
}

/* Recomputes when the wasm_timer task next has to wake the WASM thread. */
static void cap_wasm_timer_reschedule(void)
{
    uint32_t next = UINT32_MAX;

    for (size_t i = 0; i < s_app_count; i++) {
        if (cap_wasm_timer_active(&s_apps[i]) && s_apps[i].timer_due_s < next) {
            next = s_apps[i].timer_due_s;
        }
    }
    atomic_store(&s_timer_next_s, next);
}

/* Due time of a long timer from its last run, once the clock is set: overdue runs one minute from now. */
static void cap_wasm_timer_resync(cap_wasm_app_t *app)
{
    uint32_t now_unix = (uint32_t)time(NULL);
    uint32_t elapsed = now_unix > app->timer_last ? now_unix - app->timer_last : 0;
    uint32_t wait = elapsed >= app->timer_s ? 0 : app->timer_s - elapsed;

    app->timer_resync = false;
    app->timer_due_s = cap_wasm_uptime_s() + (wait > CAP_WASM_TIMER_MIN_S ? wait : CAP_WASM_TIMER_MIN_S);
}

static void cap_wasm_timer_resync_all(void)
{
    bool changed = false;

    for (size_t i = 0; i < s_app_count; i++) {
        if (s_apps[i].timer_resync && s_apps[i].timer_s && cap_wasm_clock_set()) {
            cap_wasm_timer_resync(&s_apps[i]);
            changed = true;
        }
    }
    if (changed) {
        cap_wasm_timer_reschedule();
    }
}

/* Loads the persisted timer of an app that was (re)loaded, enabled or installed; clears failures. */
static void cap_wasm_timer_restore(cap_wasm_app_t *app)
{
    uint32_t last = 0;
    uint32_t interval = app->mf.perms & CAP_WASM_PERM_TIMER ? cap_wasm_timer_load(app->name, &last) : 0;

    if (!(app->mf.perms & CAP_WASM_PERM_TIMER)) {
        cap_wasm_timer_store(app->name, 0); /* the update dropped the permission */
    } else if (interval && (interval < app->mf.timer_min_s || interval > CAP_WASM_TIMER_MAX_S)) {
        interval = interval < app->mf.timer_min_s ? app->mf.timer_min_s : CAP_WASM_TIMER_MAX_S;
        cap_wasm_timer_store(app->name, interval);
    }
    app->timer_s = interval;
    app->timer_off = false;
    app->timer_failures = 0;
    app->timer_error[0] = '\0';
    app->timer_last = interval >= CAP_WASM_TIMER_PERSIST_S ? last : 0;
    app->timer_due_s = cap_wasm_uptime_s() + interval;
    app->timer_resync = app->timer_last != 0;
    if (app->timer_resync && cap_wasm_clock_set()) {
        cap_wasm_timer_resync(app);
    }
    cap_wasm_timer_reschedule();
}

int32_t cap_wasm_timer_set(cap_wasm_app_t *app, int32_t interval_s)
{
    size_t active = 0;

    if (interval_s != 0 && (interval_s < (int32_t)app->mf.timer_min_s || interval_s > CAP_WASM_TIMER_MAX_S)) {
        ESP_LOGW(TAG, "[%s] timer_set(%" PRId32 "): allowed are 0 or %" PRIu32 "-%d s", app->name, interval_s,
                 app->mf.timer_min_s, CAP_WASM_TIMER_MAX_S);
        return -CAP_WASM_EINVAL;
    }
    if ((uint32_t)interval_s == app->timer_s) {
        return 0; /* app_init may set it on every load: keep the schedule and spare the flash */
    }
    for (size_t i = 0; i < s_app_count; i++) {
        active += &s_apps[i] != app && s_apps[i].name[0] && s_apps[i].timer_s;
    }
    if (interval_s && !app->timer_s && active >= CAP_WASM_MAX_TIMERS) {
        ESP_LOGW(TAG, "[%s] timer_set: %d apps have a timer already", app->name, CAP_WASM_MAX_TIMERS);
        return -CAP_WASM_ENOSPC;
    }
    app->timer_s = (uint32_t)interval_s;
    app->timer_due_s = cap_wasm_uptime_s() + app->timer_s;
    app->timer_last = 0;
    app->timer_resync = false;
    cap_wasm_timer_store(app->name, app->timer_s);
    cap_wasm_timer_reschedule();
    ESP_LOGI(TAG, "[%s] timer %s%" PRIu32 "%s", app->name, interval_s ? "every " : "cancelled", app->timer_s,
             interval_s ? " s" : "");
    return 0;
}

/* Runs one app's on_timer() like a tool call (same budget), with a context that has no chat. */
static void cap_wasm_run_timer(cap_wasm_app_t *app)
{
    static const claw_cap_call_context_t ctx = {
        .caller = CLAW_CAP_CALLER_SYSTEM,
        .source_cap = "cap_wasm_timer",
    };
    cap_wasm_call_t *call = &g_cap_wasm_call;
    char output[64];
    char msg[256];
    bool ok = false;
    bool terminated = false;

    app->timer_due_s = cap_wasm_uptime_s() + app->timer_s;
    app->timer_runs++;
    if (!cap_wasm_ensure_loaded(app)) {
        snprintf(app->timer_error, sizeof(app->timer_error), "cannot load: %.80s", app->last_error);
    } else if (!app->inst) {
        app->tools_frozen = true;
        ok = cap_wasm_instantiate(app);
        app->tools_frozen = false;
        if (!ok) {
            snprintf(app->timer_error, sizeof(app->timer_error), "cannot restart: %.78s", app->last_error);
        }
    } else {
        ok = true;
    }
    if (ok) {
        *call = (cap_wasm_call_t) {
            .app = app,
            .ctx = &ctx,
            .output = output,
            .output_size = sizeof(output),
        };
        cap_wasm_budget_begin(app, app->mf.call_timeout_ms);
        ok = wasm_runtime_call_wasm(app->env, app->fn_timer, 0, NULL);
        terminated = cap_wasm_budget_end();
        heap_caps_free(call->resp);
        *call = (cap_wasm_call_t) {0};
        app->last_used_us = esp_timer_get_time();
        if (!ok && terminated) {
            snprintf(app->timer_error, sizeof(app->timer_error), "on_timer exceeded %" PRIu32 " ms",
                     app->mf.call_timeout_ms);
        } else if (!ok) {
            snprintf(app->timer_error, sizeof(app->timer_error), "on_timer trapped: %.60s",
                     wasm_runtime_get_exception(app->inst));
        }
        if (!ok || terminated) {
            cap_wasm_teardown(app); /* a trapped or terminated instance is recreated on the next call */
        }
    }
    if (app->tools_changed) {
        cap_wasm_schedule_refresh(app);
    }
    if (ok) {
        app->timer_failures = 0;
        if (app->timer_s >= CAP_WASM_TIMER_PERSIST_S && cap_wasm_clock_set()) {
            app->timer_last = (uint32_t)time(NULL);
            cap_wasm_timer_store_last(app->name, app->timer_last);
        }
        return;
    }
    if (++app->timer_failures < CAP_WASM_TIMER_MAX_FAILURES) {
        ESP_LOGW(TAG, "[%s] timer run failed (%u/%d): %s", app->name, app->timer_failures,
                 CAP_WASM_TIMER_MAX_FAILURES, app->timer_error);
        return;
    }
    app->timer_off = true;
    ESP_LOGE(TAG, "[%s] timer stopped after %d failed runs: %s", app->name, CAP_WASM_TIMER_MAX_FAILURES,
             app->timer_error);
    snprintf(msg, sizeof(msg), "⏰ App `%s`: timer stopped after %d failed runs (%s). /apps reload %s restarts it.",
             app->name, CAP_WASM_TIMER_MAX_FAILURES, app->timer_error, app->name);
    cap_wasm_send_allowed(msg);
}

/* REQ_TIMER: runs the most overdue timer; ESP_ERR_NOT_FOUND when none is due. */
static void cap_wasm_do_timer(cap_wasm_req_t *req)
{
    uint32_t now = cap_wasm_uptime_s();
    cap_wasm_app_t *due = NULL;

    for (size_t i = 0; i < s_app_count; i++) {
        cap_wasm_app_t *app = &s_apps[i];

        if (cap_wasm_timer_active(app) && app->timer_due_s <= now && (!due || app->timer_due_s < due->timer_due_s)) {
            due = app;
        }
    }
    req->err = due ? ESP_OK : ESP_ERR_NOT_FOUND;
    if (due) {
        cap_wasm_run_timer(due);
    }
}

static void cap_wasm_render_status(char *out, size_t size, bool json)
{
    cJSON *list = json ? cJSON_CreateArray() : NULL;
    int64_t now = esp_timer_get_time();
    uint32_t now_s = cap_wasm_uptime_s();
    size_t len = 0;
    char *rendered;

    out[0] = '\0';
    for (size_t i = 0; i < s_app_count; i++) {
        cap_wasm_app_t *app = &s_apps[i];
        wasm_memory_inst_t mem = app->inst ? wasm_runtime_get_default_memory(app->inst) : NULL;
        uint32_t mem_kb = mem ? (uint32_t)(wasm_memory_get_cur_page_count(mem) * 64) : 0;
        int64_t idle_s = app->last_used_us ? (now - app->last_used_us) / 1000000 : -1;

        if (!app->name[0]) {
            continue;
        }
        if (json) {
            cJSON *item = cJSON_CreateObject();
            cJSON *tools = cJSON_AddArrayToObject(item, "tools");

            cJSON_AddStringToObject(item, "name", app->name);
            cJSON_AddStringToObject(item, "version", app->mf.version);
            cJSON_AddStringToObject(item, "state", cap_wasm_state_name(app->state));
            cJSON_AddBoolToObject(item, "enabled", app->enabled);
            cJSON_AddBoolToObject(item, "loaded", app->module != NULL);
            cJSON_AddStringToObject(item, "key_id", app->key_id);
            cJSON_AddStringToObject(item, "description", app->mf.description);
            for (size_t t = 0; t < s_tool_count; t++) {
                if (s_tools[t].app == app) {
                    cJSON_AddItemToArray(tools, cJSON_CreateString(s_tools[t].name));
                }
            }
            if (app->module) {
                cJSON_AddNumberToObject(item, "psram_bytes", app->psram_bytes);
                cJSON_AddNumberToObject(item, "memory_kb", mem_kb);
            }
            cJSON_AddNumberToObject(item, "memory_cap_kb", app->mf.memory_kb);
            cJSON_AddNumberToObject(item, "calls", app->calls);
            if (idle_s >= 0) {
                cJSON_AddNumberToObject(item, "last_used_s_ago", (double)idle_s);
            }
            cJSON_AddNumberToObject(item, "failures", app->failures);
            if (app->installed_at) {
                cJSON_AddNumberToObject(item, "installed_at", app->installed_at);
            }
            if (app->last_error[0]) {
                cJSON_AddStringToObject(item, "last_error", app->last_error);
            }
            if (app->timer_s) {
                cJSON *timer = cJSON_AddObjectToObject(item, "timer");

                cJSON_AddNumberToObject(timer, "interval_s", app->timer_s);
                cJSON_AddStringToObject(timer, "state", app->timer_off ? "stopped" :
                                        cap_wasm_timer_active(app) ? "active" : "inactive");
                if (cap_wasm_timer_active(app)) {
                    cJSON_AddNumberToObject(timer, "next_in_s", app->timer_due_s > now_s ? app->timer_due_s - now_s : 0);
                }
                cJSON_AddNumberToObject(timer, "runs", app->timer_runs);
                cJSON_AddNumberToObject(timer, "failures", app->timer_failures);
                if (app->timer_error[0]) {
                    cJSON_AddStringToObject(timer, "last_error", app->timer_error);
                }
            }
            cJSON_AddItemToArray(list, item);
            continue;
        }
        len += snprintf(out + len, len < size ? size - len : 0, "%s`%s` %s — %s", len ? "\n" : "", app->name,
                        app->mf.version[0] ? app->mf.version : "?", cap_wasm_state_name(app->state));
        if (app->module) {
            len += snprintf(out + len, len < size ? size - len : 0, ", psram %" PRIu32 " KB, mem %" PRIu32 "/%" PRIu32 " KB",
                            app->psram_bytes / 1024, mem_kb, app->mf.memory_kb);
        }
        len += snprintf(out + len, len < size ? size - len : 0, ", key %s, calls %" PRIu32,
                        app->key_id[0] ? app->key_id : "none", app->calls);
        if (idle_s >= 0) {
            len += snprintf(out + len, len < size ? size - len : 0, ", last used %" PRId64 " s ago", idle_s);
        }
        len += snprintf(out + len, len < size ? size - len : 0, "\n");
        for (size_t t = 0; t < s_tool_count; t++) {
            if (s_tools[t].app == app) {
                len += snprintf(out + len, len < size ? size - len : 0, "  tool `%s`\n", s_tools[t].name);
            }
        }
        if (app->last_error[0]) {
            len += snprintf(out + len, len < size ? size - len : 0, "  last error: %s\n", app->last_error);
        }
        if (app->timer_off) {
            len += snprintf(out + len, len < size ? size - len : 0, "  timer every %" PRIu32 " s stopped after %u "
                            "failures: %s\n", app->timer_s, app->timer_failures, app->timer_error);
        } else if (cap_wasm_timer_active(app)) {
            len += snprintf(out + len, len < size ? size - len : 0, "  timer every %" PRIu32 " s, next in %" PRIu32
                            " s, %" PRIu32 " runs%s%s\n", app->timer_s,
                            app->timer_due_s > now_s ? app->timer_due_s - now_s : 0, app->timer_runs,
                            app->timer_error[0] ? ", last error: " : "", app->timer_error);
        } else if (app->timer_s) {
            len += snprintf(out + len, len < size ? size - len : 0, "  timer every %" PRIu32 " s (inactive)\n",
                            app->timer_s);
        }
    }
    if (json) {
        rendered = list ? cJSON_PrintUnformatted(list) : NULL;
        snprintf(out, size, "%s", rendered ? rendered : "Error: out of memory");
        free(rendered);
        cJSON_Delete(list);
    } else if (!len) {
        snprintf(out, size, "No WASM apps. /app install <https-url> installs a signed .ecapp package.");
    }
}

static cap_wasm_app_t *cap_wasm_find_app(const char *name)
{
    for (size_t i = 0; i < s_app_count; i++) {
        if (s_apps[i].name[0] && strcmp(s_apps[i].name, name) == 0) {
            return &s_apps[i];
        }
    }
    return NULL;
}

/* Adds a slot for a directory name; NULL when invalid or full. */
static cap_wasm_app_t *cap_wasm_add_app(const char *name)
{
    cap_wasm_app_t *app = NULL;

    if (!cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX)) {
        ESP_LOGW(TAG, "ignoring %s/%s: app names are 1-%d chars of [a-z0-9_] starting with a letter",
                 g_cap_wasm_apps_dir, name, CAP_WASM_APP_NAME_MAX);
        return NULL;
    }
    for (size_t i = 0; i < s_app_count && !app; i++) {
        app = s_apps[i].name[0] ? NULL : &s_apps[i];
    }
    if (!app && s_app_count >= CAP_WASM_MAX_APPS) {
        ESP_LOGW(TAG, "ignoring %s/%s: at most %d apps", g_cap_wasm_apps_dir, name, CAP_WASM_MAX_APPS);
        return NULL;
    }
    app = app ? app : &s_apps[s_app_count++];
    memset(app, 0, sizeof(*app));
    strlcpy(app->name, name, sizeof(app->name));
    app->enabled = true;
    return app;
}

/* ---------- index.json: installed apps and whether they are enabled ---------- */

static void cap_wasm_index_save(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(root, "apps");
    char path[96];
    char *json;

    for (size_t i = 0; i < s_app_count; i++) {
        cap_wasm_app_t *app = &s_apps[i];
        cJSON *item;

        if (!app->name[0]) {
            continue;
        }
        item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "name", app->name);
        cJSON_AddStringToObject(item, "version", app->mf.version);
        cJSON_AddStringToObject(item, "key_id", app->key_id);
        cJSON_AddStringToObject(item, "state", app->enabled ? "enabled" : "disabled");
        cJSON_AddNumberToObject(item, "installed_at", app->installed_at);
        cJSON_AddStringToObject(item, "source", app->source_url);
        cJSON_AddItemToArray(list, item);
    }
    json = cJSON_Print(root);
    snprintf(path, sizeof(path), "%s/index.json", g_cap_wasm_apps_dir);
    if (!json || !cap_wasm_write_file_atomic(path, json)) {
        ESP_LOGE(TAG, "cannot write %s", path);
    }
    free(json);
    cJSON_Delete(root);
}

static void cap_wasm_index_load(void)
{
    char path[96];
    size_t size = 0;
    char *json;
    cJSON *root;
    const cJSON *item = NULL;

    snprintf(path, sizeof(path), "%s/index.json", g_cap_wasm_apps_dir);
    json = cap_wasm_read_file(path, 16 * 1024, &size);
    root = json ? cJSON_Parse(json) : NULL;
    heap_caps_free(json);
    cJSON_ArrayForEach(item, cJSON_GetObjectItem(root, "apps")) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
        const char *state = cJSON_GetStringValue(cJSON_GetObjectItem(item, "state"));
        const char *source = cJSON_GetStringValue(cJSON_GetObjectItem(item, "source"));
        cap_wasm_app_t *app = name ? cap_wasm_find_app(name) : NULL;

        if (app) {
            app->enabled = !state || strcmp(state, "disabled") != 0;
            app->installed_at = (uint32_t)cJSON_GetNumberValue(cJSON_GetObjectItem(item, "installed_at"));
            strlcpy(app->source_url, source ? source : "", sizeof(app->source_url));
        }
    }
    cJSON_Delete(root);
}

/* An install interrupted between moving the old version aside and loading the new one leaves
 * <name>.old/: put it back. Leftover <name>.new/ directories are partial downloads. */
static void cap_wasm_recover_installs(void)
{
    char names[CAP_WASM_MAX_APPS * 2][CAP_WASM_APP_NAME_MAX + 5];
    size_t count = 0;
    DIR *dir = opendir(g_cap_wasm_apps_dir);
    struct dirent *ent;
    char path[96];
    char base[96];

    while (dir && (ent = readdir(dir)) != NULL && count < sizeof(names) / sizeof(names[0])) {
        size_t len = strlen(ent->d_name);

        if (len > 4 && len < sizeof(names[0]) &&
                (strcmp(ent->d_name + len - 4, ".new") == 0 || strcmp(ent->d_name + len - 4, ".old") == 0)) {
            strcpy(names[count++], ent->d_name);
        }
    }
    if (dir) {
        closedir(dir);
    }
    for (size_t i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/%s", g_cap_wasm_apps_dir, names[i]);
        snprintf(base, sizeof(base), "%s/%.*s", g_cap_wasm_apps_dir, (int)strlen(names[i]) - 4, names[i]);
        if (strcmp(names[i] + strlen(names[i]) - 4, ".new") == 0) {
            cap_wasm_rmdir(path);
        } else if (cap_wasm_rmdir(base) && rename(path, base) == 0) {
            ESP_LOGW(TAG, "rolled back the interrupted install of %s", base);
        }
    }
}

static void cap_wasm_do_boot(void)
{
    DIR *dir;
    struct dirent *ent;

    if (g_cap_wasm_trusted_count == 0 && !s_allow_unsigned) {
        ESP_LOGW(TAG, "app_trusted_keys is empty: no WASM app can load");
    }
    cap_wasm_recover_installs();
    dir = opendir(g_cap_wasm_apps_dir);
    if (!dir) {
        ESP_LOGI(TAG, "no %s directory, no WASM apps", g_cap_wasm_apps_dir);
        return;
    }
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] != '.' && ent->d_type == DT_DIR) {
            cap_wasm_add_app(ent->d_name);
        }
    }
    closedir(dir);
    cap_wasm_index_load();
    for (size_t i = 0; i < s_app_count; i++) {
        cap_wasm_probe(&s_apps[i], true);
    }
}

/* Moves <name>.new/ into place and loads it; the previous version is restored if that fails. */
static bool cap_wasm_do_install(cap_wasm_app_t *app, const char *source, char *out, size_t size)
{
    char dir[96];
    char new_dir[sizeof(dir) + 4];
    char old_dir[sizeof(dir) + 4];
    bool was_enabled = app->enabled;
    bool had_old;

    snprintf(dir, sizeof(dir), "%s/%s", g_cap_wasm_apps_dir, app->name);
    snprintf(new_dir, sizeof(new_dir), "%s.new", dir);
    snprintf(old_dir, sizeof(old_dir), "%s.old", dir);
    cap_wasm_rmdir(old_dir);
    had_old = access(dir, F_OK) == 0;
    if ((had_old && rename(dir, old_dir) != 0) || rename(new_dir, dir) != 0) {
        if (had_old) {
            rename(old_dir, dir);
        }
        snprintf(out, size, "Install failed: cannot move %s into place.", new_dir);
        return false;
    }
    app->enabled = true;
    if (cap_wasm_load(app, false, false)) {
        cap_wasm_rmdir(old_dir);
        cap_wasm_cfg_prune(app);
        cap_wasm_timer_restore(app);
        app->installed_at = (uint32_t)time(NULL);
        strlcpy(app->source_url, source && strlen(source) < sizeof(app->source_url) ? source : "",
                sizeof(app->source_url));
        snprintf(out, size, "Installed `%s` %s: %u tools.%s%s", app->name, app->mf.version,
                 (unsigned)cap_wasm_app_tool_count(app), app->mf.setting_count ? "\nSettings: /app config " : "",
                 app->mf.setting_count ? app->name : "");
        return true;
    }
    snprintf(out, size, "Install of `%s` failed: %s", app->name, app->last_error);
    cap_wasm_rmdir(dir);
    if (had_old && rename(old_dir, dir) == 0) {
        app->enabled = was_enabled;
        cap_wasm_probe(app, false);
        snprintf(out + strlen(out), size - strlen(out), "\nKept the previous version (%s).",
                 cap_wasm_state_name(app->state));
    } else if (!had_old) {
        memset(app, 0, sizeof(*app));
    }
    return false;
}

static void cap_wasm_do_admin(cap_wasm_req_t *req)
{
    cap_wasm_app_t *app = cap_wasm_find_app(req->arg);
    char path[96];
    struct stat st;
    nvs_handle_t nvs;

    req->err = ESP_OK;
    snprintf(path, sizeof(path), "%s/%s%s", g_cap_wasm_apps_dir, req->arg,
             req->type == CAP_WASM_REQ_INSTALL ? ".new" : "");
    if (!app && (req->type == CAP_WASM_REQ_RELOAD || req->type == CAP_WASM_REQ_ENABLE ||
                 req->type == CAP_WASM_REQ_INSTALL)) {
        app = stat(path, &st) == 0 && S_ISDIR(st.st_mode) ? cap_wasm_add_app(req->arg) : NULL;
    }
    if (!app) {
        snprintf(req->output, req->output_size, "No WASM app '%s'.", req->arg);
        req->err = ESP_ERR_NOT_FOUND;
        return;
    }

    switch (req->type) {
    case CAP_WASM_REQ_LOAD:
        if (!cap_wasm_ensure_loaded(app)) {
            snprintf(req->output, req->output_size, "Cannot load `%s` (%s): %s", app->name,
                     cap_wasm_state_name(app->state), app->last_error);
            req->err = ESP_FAIL;
        } else {
            app->last_used_us = esp_timer_get_time();
            snprintf(req->output, req->output_size, "`%s` is loaded (psram %" PRIu32 " KB, load %" PRIu32 " ms).",
                     app->name, app->psram_bytes / 1024, app->load_ms);
        }
        if (app->tools_changed) {
            cap_wasm_schedule_refresh(app);
        }
        return;
    case CAP_WASM_REQ_UNLOAD:
        snprintf(req->output, req->output_size, "`%s` %s.", app->name, app->module ? "unloaded" : "was not loaded");
        cap_wasm_unload(app);
        return;
    case CAP_WASM_REQ_CONFIG:
    case CAP_WASM_REQ_CONFIG_JSON:
        req->err = cap_wasm_cfg_command(app, req->extra, req->type == CAP_WASM_REQ_CONFIG_JSON, req->output,
                                        req->output_size);
        return;
    case CAP_WASM_REQ_DISABLE:
        cap_wasm_unload(app);
        cap_wasm_remove_tools(app);
        app->enabled = false;
        app->state = CAP_WASM_APP_DISABLED;
        snprintf(app->last_error, sizeof(app->last_error), "disabled; /apps enable %s turns it on", app->name);
        cap_wasm_index_save();
        snprintf(req->output, req->output_size, "Disabled `%s` (persists across reboots).", app->name);
        return;
    case CAP_WASM_REQ_REMOVE:
        cap_wasm_unload(app);
        cap_wasm_remove_tools(app);
        snprintf(path, sizeof(path), "%s/%s", g_cap_wasm_apps_dir, app->name);
        if (!cap_wasm_rmdir(path)) {
            snprintf(req->output, req->output_size, "Could not delete %s completely.", path);
            req->err = ESP_FAIL;
        } else {
            snprintf(req->output, req->output_size, "Removed `%s`.", app->name);
        }
        cap_wasm_nvs_namespace(app->name, app->nvs_ns);
        if (nvs_open(app->nvs_ns, NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_erase_all(nvs);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
        cap_wasm_cfg_erase(app->name);
        memset(app, 0, sizeof(*app));
        cap_wasm_index_save();
        return;
    case CAP_WASM_REQ_INSTALL:
        cap_wasm_unload(app);
        cap_wasm_remove_tools(app);
        if (!cap_wasm_do_install(app, req->extra, req->output, req->output_size)) {
            req->err = ESP_FAIL;
        }
        cap_wasm_index_save();
        return;
    default: /* RELOAD, ENABLE */
        break;
    }

    if (req->type == CAP_WASM_REQ_RELOAD && !app->enabled) {
        snprintf(req->output, req->output_size, "`%s` is disabled; /apps enable %s turns it on.", app->name, app->name);
        req->err = ESP_ERR_INVALID_STATE;
        return;
    }
    cap_wasm_unload(app);
    cap_wasm_remove_tools(app);
    if (req->type == CAP_WASM_REQ_ENABLE) {
        app->enabled = true;
        cap_wasm_probe(app, false);
        cap_wasm_index_save();
    } else {
        cap_wasm_load(app, false, false);
        cap_wasm_timer_restore(app);
    }
    if (app->state == CAP_WASM_APP_LOADED || app->state == CAP_WASM_APP_UNLOADED) {
        snprintf(req->output, req->output_size, "%s `%s` %s: %u tools.",
                 req->type == CAP_WASM_REQ_ENABLE ? "Enabled" : "Reloaded", app->name, app->mf.version,
                 (unsigned)cap_wasm_app_tool_count(app));
    } else {
        snprintf(req->output, req->output_size, "`%s` is %s: %s", app->name, cap_wasm_state_name(app->state),
                 app->last_error);
        req->err = ESP_FAIL;
    }
}

/* The WASM thread. A pthread because WAMR's ESP-IDF port calls pthread_self() on every call. */
static void *cap_wasm_task(void *arg)
{
    RuntimeInitArgs init_args = {
        .mem_alloc_type = Alloc_With_Allocator,
        .mem_alloc_option.allocator = {
            .malloc_func = cap_wasm_malloc,
            .realloc_func = cap_wasm_realloc,
            .free_func = cap_wasm_free,
        },
        .native_module_name = "claw",
        .native_symbols = g_cap_wasm_natives,
        .n_native_symbols = g_cap_wasm_native_count,
        /* The thread manager is only used for wasm_runtime_terminate(); apps cannot spawn threads.
         * It splits a module's aux stack by (max_thread_num + 1) and 0 means its default of 4. */
        .max_thread_num = 1,
    };
    cap_wasm_req_t *req;

    (void)arg;
    /* Untrusted code runs at idle priority: a busy app (up to its 30 s budget) cannot starve other
     * tasks, and the idle tasks still run so the task watchdog stays fed. */
    vTaskPrioritySet(NULL, tskIDLE_PRIORITY);
    s_runtime_ok = wasm_runtime_full_init(&init_args);
    if (!s_runtime_ok) {
        ESP_LOGE(TAG, "wasm_runtime_full_init failed, WASM apps are unavailable");
    }
    while (true) {
        if (xQueueReceive(s_req_queue, &req, pdMS_TO_TICKS(CAP_WASM_SWEEP_MS)) != pdTRUE) {
            cap_wasm_idle_sweep();
            cap_wasm_timer_resync_all();
            continue;
        }
        if (!s_runtime_ok) {
            snprintf(req->output, req->output_size, "Error: WASM runtime failed to start");
            req->err = ESP_ERR_INVALID_STATE;
        } else if (req->type == CAP_WASM_REQ_BOOT) {
            cap_wasm_do_boot();
        } else if (req->type == CAP_WASM_REQ_CALL) {
            cap_wasm_do_call(req);
        } else if (req->type == CAP_WASM_REQ_TIMER) {
            cap_wasm_do_timer(req);
        } else if (req->type == CAP_WASM_REQ_STATUS) {
            cap_wasm_render_status(req->output, req->output_size, req->arg != NULL);
            req->err = ESP_OK;
        } else {
            cap_wasm_do_admin(req);
        }
        cap_wasm_timer_reschedule(); /* any request may have changed an app's state or timer */
        xSemaphoreGive(s_done);
        cap_wasm_idle_sweep();
        cap_wasm_timer_resync_all();
    }
    return NULL;
}

/* Hands a request to the WASM thread and watches its budget until it is done. */
static esp_err_t cap_wasm_submit(cap_wasm_req_t *req, TickType_t lock_wait)
{
    if (!s_call_lock) {
        snprintf(req->output, req->output_size, "Error: WASM apps are not running");
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(s_call_lock, lock_wait) != pdTRUE) {
        snprintf(req->output, req->output_size, "Error: WASM apps are busy, try again");
        return ESP_ERR_TIMEOUT;
    }
    xQueueSend(s_req_queue, &req, portMAX_DELAY);
    while (xSemaphoreTake(s_done, pdMS_TO_TICKS(CAP_WASM_WATCHDOG_TICK_MS)) != pdTRUE) {
        cap_wasm_watchdog();
    }
    xSemaphoreGive(s_call_lock);
    return req->err;
}

/* Wakes the WASM thread when a timer is due and watches the on_timer() budget like any requester. */
static void cap_wasm_timer_task(void *arg)
{
    char unused[1];
    cap_wasm_req_t req = {
        .type = CAP_WASM_REQ_TIMER,
        .output = unused,
        .output_size = sizeof(unused),
    };

    (void)arg;
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(CAP_WASM_TIMER_TICK_MS));
        /* Several due timers run back to back; a busy runtime is retried on the next tick. */
        while (cap_wasm_uptime_s() >= atomic_load(&s_timer_next_s) &&
                cap_wasm_submit(&req, pdMS_TO_TICKS(CAP_WASM_DRAIN_MS)) == ESP_OK) {
        }
    }
}

/* ---------- claw_cap bridge ---------- */

static esp_err_t cap_wasm_tool_call(int slot, const char *input_json, const claw_cap_call_context_t *ctx,
                                    char *output, size_t output_size)
{
    cap_wasm_req_t req = {
        .type = CAP_WASM_REQ_CALL,
        .slot = slot,
        .arg = input_json ? input_json : "{}",
        .ctx = ctx,
        .output = output,
        .output_size = output_size,
    };
    int64_t t0 = esp_timer_get_time();
    esp_err_t err = cap_wasm_submit(&req, portMAX_DELAY);

    ESP_LOGI(TAG, "call %s: %" PRId64 " ms, %.120s", s_tools[slot].name, (esp_timer_get_time() - t0) / 1000,
             err == ESP_OK ? "ok" : output);
    return err;
}

/* claw_cap execute callbacks carry no descriptor or user context, so each tool slot gets its own
 * trampoline. CAP_WASM_MAX_TOOLS must match the slot count. */
#define CAP_WASM_SLOTS(X) \
    X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15) \
    X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23) X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)
#define CAP_WASM_SLOT_FN(n)                                                                             \
    static esp_err_t cap_wasm_slot_##n(const char *input_json, const claw_cap_call_context_t *ctx,      \
                                       char *output, size_t output_size)                                \
    {                                                                                                   \
        return cap_wasm_tool_call(n, input_json, ctx, output, output_size);                             \
    }
#define CAP_WASM_SLOT_REF(n) cap_wasm_slot_##n,
CAP_WASM_SLOTS(CAP_WASM_SLOT_FN)
static const claw_cap_execute_fn s_slot_fns[] = { CAP_WASM_SLOTS(CAP_WASM_SLOT_REF) };
_Static_assert(sizeof(s_slot_fns) / sizeof(s_slot_fns[0]) == CAP_WASM_MAX_TOOLS, "one trampoline per tool slot");

/* (Re-)registers the cap_wasm_apps group with the current tools (a group cannot be empty). */
static void cap_wasm_publish_tools(void)
{
    if (s_tool_count == 0) {
        return;
    }
    for (size_t i = 0; i < s_tool_count; i++) {
        s_descriptors[i] = (claw_cap_descriptor_t) {
            .id = s_tools[i].name,
            .name = s_tools[i].name,
            .family = "wasm_app",
            .description = s_tools[i].desc,
            .kind = CLAW_CAP_KIND_CALLABLE,
            .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
            .input_schema_json = s_tools[i].schema,
            .execute = s_slot_fns[i],
        };
    }
    s_group = (claw_cap_group_t) {
        .group_id = CAP_WASM_GROUP,
        .plugin_name = "cap_wasm_apps",
        .version = "1",
        .descriptors = s_descriptors,
        .descriptor_count = s_tool_count,
    };
    if (claw_cap_register_group(&s_group) != ESP_OK) {
        ESP_LOGE(TAG, "failed to register the %s group", CAP_WASM_GROUP);
    }
}

esp_err_t cap_wasm_admin(cap_wasm_req_type_t type, const char *name, const char *extra,
                         char *output, size_t output_size)
{
    cap_wasm_req_t req = {
        .type = type,
        .arg = name,
        .extra = extra,
        .output = output,
        .output_size = output_size,
    };
    esp_err_t err;

    if (!cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX)) {
        snprintf(output, output_size, "Invalid app name '%.32s'.", name);
        return ESP_ERR_INVALID_ARG;
    }
    if (type < CAP_WASM_REQ_RELOAD) {
        return cap_wasm_submit(&req, pdMS_TO_TICKS(CAP_WASM_DRAIN_MS));
    }
    /* The tool set may change, so the group is drained and re-registered. */
    err = claw_cap_unregister_group(CAP_WASM_GROUP, CAP_WASM_DRAIN_MS);
    if (err == ESP_ERR_TIMEOUT) {
        claw_cap_enable_group(CAP_WASM_GROUP);
        snprintf(output, output_size, "A WASM app call is still running, try again.");
        return err;
    }
    err = cap_wasm_submit(&req, portMAX_DELAY);
    cap_wasm_publish_tools();
    return err;
}

/* ---------- Management tools and /apps ---------- */

static esp_err_t cap_wasm_status(bool json, char *output, size_t output_size)
{
    cap_wasm_req_t req = {
        .type = CAP_WASM_REQ_STATUS,
        .arg = json ? "json" : NULL,
        .output = output,
        .output_size = output_size,
    };

    return cap_wasm_submit(&req, pdMS_TO_TICKS(CAP_WASM_STATUS_WAIT_MS));
}

/* Parses the tool input and returns its string field `key` (copied into `out`). */
static bool cap_wasm_input_str(const char *input_json, const char *key, char *out, size_t size)
{
    cJSON *input = cJSON_Parse(input_json);
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(input, key));
    bool ok = value && strlen(value) < size;

    if (ok) {
        strcpy(out, value);
    }
    cJSON_Delete(input);
    return ok;
}

static esp_err_t cap_wasm_status_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    (void)input_json;
    (void)ctx;
    return cap_wasm_status(true, output, output_size);
}

static esp_err_t cap_wasm_name_tool(cap_wasm_req_type_t type, const char *input_json, char *output, size_t output_size)
{
    char name[CAP_WASM_APP_NAME_MAX + 1];

    if (!cap_wasm_input_str(input_json, "name", name, sizeof(name))) {
        snprintf(output, output_size, "Error: name (an installed app) is required");
        return ESP_ERR_INVALID_ARG;
    }
    return cap_wasm_admin(type, name, NULL, output, output_size);
}

static esp_err_t cap_wasm_load_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                       char *output, size_t output_size)
{
    (void)ctx;
    return cap_wasm_name_tool(CAP_WASM_REQ_LOAD, input_json, output, output_size);
}

static esp_err_t cap_wasm_unload_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    (void)ctx;
    return cap_wasm_name_tool(CAP_WASM_REQ_UNLOAD, input_json, output, output_size);
}

static esp_err_t cap_wasm_config_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    (void)ctx;
    return cap_wasm_name_tool(CAP_WASM_REQ_CONFIG_JSON, input_json, output, output_size);
}

static esp_err_t cap_wasm_set_enabled_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                              char *output, size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    bool enabled = cJSON_IsTrue(cJSON_GetObjectItem(input, "enabled"));
    bool valid = cJSON_IsBool(cJSON_GetObjectItem(input, "enabled"));

    (void)ctx;
    cJSON_Delete(input);
    if (!valid) {
        snprintf(output, output_size, "Error: enabled (boolean) is required");
        return ESP_ERR_INVALID_ARG;
    }
    return cap_wasm_name_tool(enabled ? CAP_WASM_REQ_ENABLE : CAP_WASM_REQ_DISABLE, input_json, output, output_size);
}

static esp_err_t cap_wasm_install_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                          char *output, size_t output_size)
{
    char url[256];

    if (!cap_wasm_input_str(input_json, "url", url, sizeof(url))) {
        snprintf(output, output_size, "Error: url (https, at most 255 chars) is required");
        return ESP_ERR_INVALID_ARG;
    }
    return cap_wasm_install(url, NULL, NULL, false, false, ctx, output, output_size);
}

static esp_err_t cap_wasm_remove_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    char name[CAP_WASM_APP_NAME_MAX + 1];

    if (!cap_wasm_input_str(input_json, "name", name, sizeof(name))) {
        snprintf(output, output_size, "Error: name (an installed app) is required");
        return ESP_ERR_INVALID_ARG;
    }
    return cap_wasm_remove(name, ctx, output, output_size);
}

static esp_err_t cap_wasm_command_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                          char *output, size_t output_size)
{
    static const struct {
        const char *verb;
        cap_wasm_req_type_t type;
    } verbs[] = {
        {"reload", CAP_WASM_REQ_RELOAD},
        {"enable", CAP_WASM_REQ_ENABLE},
        {"disable", CAP_WASM_REQ_DISABLE},
        {"load", CAP_WASM_REQ_LOAD},
        {"unload", CAP_WASM_REQ_UNLOAD},
    };
    char command[512] = "";
    char verb[16] = "";
    char name[CAP_WASM_APP_NAME_MAX + 2] = "";
    esp_err_t err = ESP_OK;
    int args_at = 0;

    if (!cap_wasm_input_str(input_json, "command", command, sizeof(command)) && strstr(input_json, "command")) {
        snprintf(output, output_size, "Error: the command is longer than %u bytes", (unsigned)sizeof(command) - 1);
        return ESP_ERR_INVALID_ARG;
    }
    sscanf(command, "%15s %25s%n", verb, name, &args_at);
    if (!verb[0] || strcmp(verb, "list") == 0) {
        return cap_wasm_status(false, output, output_size);
    }
    if (strcmp(verb, "config") == 0 && name[0]) {
        const char *args = command + args_at;

        /* Values are set by the user only: a Telegram slash command, never the agent or Lua (which
         * cannot claim source_cap tg_gateway). */
        if (args[strspn(args, " ")] &&
                (!ctx || ctx->caller != CLAW_CAP_CALLER_SYSTEM || !cap_im_tg_confirm_chat(ctx))) {
            snprintf(output, output_size, "Error: app settings can only be changed with /app config in Telegram");
            return ESP_ERR_NOT_SUPPORTED;
        }
        return cap_wasm_admin(CAP_WASM_REQ_CONFIG, name, args, output, output_size);
    }
    if (strcmp(verb, "install") == 0 || strcmp(verb, "update") == 0 || strcmp(verb, "updates") == 0 ||
            strcmp(verb, "remove") == 0) {
        /* Confirmation is answered through the Telegram poll task this handler runs on. */
        const char *chat = cap_im_tg_confirm_chat(ctx);

        err = chat ? cap_wasm_start_job(command, chat) : ESP_ERR_NOT_SUPPORTED;
        snprintf(output, output_size, "%s", err == ESP_OK ? "⏳ Working on it…" :
                 chat ? "Error: cannot start the installer task" : "Error: needs a Telegram chat to confirm in");
        return err;
    }
    for (size_t i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++) {
        if (strcmp(verb, verbs[i].verb) == 0 && name[0]) {
            return cap_wasm_admin(verbs[i].type, name, NULL, output, output_size);
        }
    }
    snprintf(output, output_size,
             "Usage:\n/apps  List WASM apps\n"
             "/app install [" CAP_WASM_DOWNGRADE_FLAG "] <https-url>  Install a signed .ecapp (the flag allows a "
             "version below the installed one or the anti-rollback floor)\n"
             "/app updates  List available app and firmware updates\n"
             "/app update <name>|all [url]  Update to the latest GitHub release (or from url)\n"
             "/app remove <name>  Delete an app and its data\n"
             "/app config <name>  List an app's settings\n"
             "/app config <name> <key> <value>|--reset  Set a setting or reset it to its default\n"
             "/apps enable|disable <name>  Turn an app on/off (persists)\n"
             "/apps load|unload <name>  Load into / free from memory now\n"
             "/apps reload <name>  Reload an app from %s/<name>/", g_cap_wasm_apps_dir);
    return err;
}

#define CAP_WASM_NAME_SCHEMA "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}"

static const claw_cap_descriptor_t s_mgr_descriptors[] = {
    {
        .id = "apps_command",
        .name = "apps_command",
        .family = "wasm_app",
        .description = "Handle the /apps and /app chat commands.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = cap_wasm_command_execute,
    },
    {
        .id = "apps_status",
        .name = "apps_status",
        .family = "wasm_app",
        .description = "List installed WASM apps: version, state, enabled, loaded, PSRAM use, last use, tools, last error, timer.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_wasm_status_execute,
    },
    {
        .id = "apps_load",
        .name = "apps_load",
        .family = "wasm_app",
        .description = "Load an installed WASM app into memory now (apps also load on their first tool call).",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = CAP_WASM_NAME_SCHEMA,
        .execute = cap_wasm_load_execute,
    },
    {
        .id = "apps_unload",
        .name = "apps_unload",
        .family = "wasm_app",
        .description = "Free a loaded WASM app's memory; its tools stay available and reload it on demand.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = CAP_WASM_NAME_SCHEMA,
        .execute = cap_wasm_unload_execute,
    },
    {
        .id = "apps_config",
        .name = "apps_config",
        .family = "wasm_app",
        .description = "List an installed WASM app's settings: key, type, description, whether set, and the value "
                       "(secret values are never shown). Read-only: the user sets values with /app config in Telegram.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = CAP_WASM_NAME_SCHEMA,
        .execute = cap_wasm_config_execute,
    },
    {
        .id = "apps_set_enabled",
        .name = "apps_set_enabled",
        .family = "wasm_app",
        .description = "Enable or disable an installed WASM app (persists across reboots; disabled apps have no tools).",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"},"
                             "\"enabled\":{\"type\":\"boolean\"}},\"required\":[\"name\",\"enabled\"]}",
        .execute = cap_wasm_set_enabled_execute,
    },
    {
        .id = "apps_install",
        .name = "apps_install",
        .family = "wasm_app",
        .description = "Install or update a signed WASM app package (.ecapp) from an https URL. The user confirms "
                       "in Telegram; only works in a Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\"}},\"required\":[\"url\"]}",
        .execute = cap_wasm_install_execute,
    },
    {
        .id = "apps_remove",
        .name = "apps_remove",
        .family = "wasm_app",
        .description = "Remove an installed WASM app and its stored data. The user confirms in Telegram; only works "
                       "in a Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = CAP_WASM_NAME_SCHEMA,
        .execute = cap_wasm_remove_execute,
    },
    {
        .id = "apps_check_updates",
        .name = "apps_check_updates",
        .family = "wasm_app",
        .description = "List the installed and the latest available versions of the firmware and of every WASM "
                       "app installed from a GitHub release.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_wasm_check_updates_execute,
    },
    {
        .id = "apps_update",
        .name = "apps_update",
        .family = "wasm_app",
        .description = "Update an installed WASM app (name) or every app with an update (\"all\") to its latest "
                       "GitHub release. The user confirms in Telegram; only works in a Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = CAP_WASM_NAME_SCHEMA,
        .execute = cap_wasm_update_execute,
    },
    {
        .id = "firmware_command",
        .name = "firmware_command",
        .family = "firmware",
        .description = "Handle the /fw chat command.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = cap_wasm_fw_command_execute,
    },
    {
        .id = "firmware_status",
        .name = "firmware_status",
        .family = "firmware",
        .description = "Show the running firmware version and OTA slot, the other slot and the last update result.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_wasm_fw_status_execute,
    },
    {
        .id = "firmware_check",
        .name = "firmware_check",
        .family = "firmware",
        .description = "Check for a newer signed firmware: the latest GitHub release by default, or an https .bin url "
                       "(with <url>.sig.json next to it).",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\"}}}",
        .execute = cap_wasm_fw_check_execute,
    },
    {
        .id = "firmware_update",
        .name = "firmware_update",
        .family = "firmware",
        .description = "Install a newer signed firmware (latest GitHub release or an https .bin url) and reboot. "
                       "force allows a downgrade or reinstall. The user confirms in Telegram; only works in a "
                       "Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\"},"
                             "\"force\":{\"type\":\"boolean\"}}}",
        .execute = cap_wasm_fw_update_execute,
    },
};

static const claw_cap_group_t s_mgr_group = {
    .group_id = CAP_WASM_MGR_GROUP,
    .plugin_name = "cap_wasm_apps",
    .version = "1",
    .descriptors = s_mgr_descriptors,
    .descriptor_count = sizeof(s_mgr_descriptors) / sizeof(s_mgr_descriptors[0]),
};

static bool cap_wasm_start_thread(void)
{
    esp_pthread_cfg_t prev_cfg;
    esp_pthread_cfg_t cfg = esp_pthread_get_default_config();
    bool had_cfg = esp_pthread_get_cfg(&prev_cfg) == ESP_OK;
    pthread_t thread;
    int rc;

    cfg.stack_size = CAP_WASM_TASK_STACK;
    cfg.thread_name = "wasm_apps";
    cfg.stack_alloc_caps = CAP_WASM_PSRAM_CAPS;
    esp_pthread_set_cfg(&cfg);
    rc = pthread_create(&thread, NULL, cap_wasm_task, NULL);
    if (had_cfg) {
        esp_pthread_set_cfg(&prev_cfg);
    } else {
        cfg = esp_pthread_get_default_config();
        esp_pthread_set_cfg(&cfg);
    }
    if (rc != 0) {
        ESP_LOGE(TAG, "failed to create the WASM thread: %d", rc);
        return false;
    }
    pthread_detach(thread);
    return true;
}

void cap_wasm_apps_set_trust(const char *trusted_keys_json, bool allow_unsigned)
{
    cJSON *keys = cJSON_Parse(trusted_keys_json ? trusted_keys_json : "");
    const cJSON *item = NULL;
    char err[96];

    s_allow_unsigned = allow_unsigned;
    g_cap_wasm_trusted_count = 0;
    if (trusted_keys_json && trusted_keys_json[0] && !cJSON_IsArray(keys)) {
        ESP_LOGW(TAG, "app_trusted_keys is not a JSON array; no keys trusted");
    }
    cJSON_ArrayForEach(item, (cJSON_IsArray(keys) ? keys : NULL)) {
        cap_wasm_key_t *key = &g_cap_wasm_trusted[g_cap_wasm_trusted_count];

        if (g_cap_wasm_trusted_count >= CAP_WASM_MAX_TRUSTED) {
            ESP_LOGW(TAG, "app_trusted_keys: skipping an entry (more than %d keys)", CAP_WASM_MAX_TRUSTED);
            continue;
        }
        if (!cap_wasm_key_parse_entry(item, key, err, sizeof(err))) {
            ESP_LOGW(TAG, "app_trusted_keys: skipping an entry: %s", err);
            continue;
        }
        ESP_LOGI(TAG, "trusting app signing key %s%s%s%s%s", key->key_id, key->prefix_count ? " for apps " : "",
                 key->prefix_count ? key->prefixes[0] : "", key->prefix_count ? "*" : "",
                 key->prefix_count > 1 ? ", ..." : "");
        g_cap_wasm_trusted_count++;
    }
    cJSON_Delete(keys);
}

esp_err_t cap_wasm_apps_register_group(const char *base_path)
{
    char unused[1];
    cap_wasm_req_t boot = {
        .type = CAP_WASM_REQ_BOOT,
        .output = unused,
        .output_size = sizeof(unused),
    };

    if (!base_path) {
        return ESP_ERR_INVALID_ARG;
    }
    if (claw_cap_group_exists(CAP_WASM_MGR_GROUP)) {
        return ESP_OK;
    }
    snprintf(g_cap_wasm_apps_dir, sizeof(g_cap_wasm_apps_dir), "%s/apps", base_path);

    /* Failures below are logged but never fail boot (app_claw_start would abort). Registering the
     * management group first lets app tools be checked against its names. */
    if (claw_cap_register_group(&s_mgr_group) != ESP_OK) {
        ESP_LOGE(TAG, "failed to register the %s group", CAP_WASM_MGR_GROUP);
    }
    cap_wasm_fw_boot();
    cap_wasm_updates_start();
    s_req_queue = xQueueCreate(1, sizeof(cap_wasm_req_t *));
    s_done = xSemaphoreCreateBinary();
    s_call_lock = xSemaphoreCreateMutex();
    s_exec.lock = xSemaphoreCreateMutex();
    if (!s_req_queue || !s_done || !s_call_lock || !s_exec.lock || !cap_wasm_start_thread()) {
        ESP_LOGE(TAG, "cannot start the WASM thread, WASM apps are unavailable");
        s_call_lock = NULL;
        return ESP_OK;
    }
    cap_wasm_submit(&boot, portMAX_DELAY);
    cap_wasm_publish_tools();
    if (xTaskCreateWithCaps(cap_wasm_timer_task, "wasm_timer", CAP_WASM_TIMER_STACK, NULL, 4, NULL,
                            CAP_WASM_PSRAM_CAPS) != pdPASS) {
        ESP_LOGE(TAG, "cannot start the app timer task; app timers do not run");
    }
    return ESP_OK;
}

esp_err_t cap_wasm_apps_status_json(char *out, size_t size)
{
    return cap_wasm_status(true, out, size);
}

esp_err_t cap_wasm_apps_set_enabled(const char *name, bool enabled, char *out, size_t size)
{
    /* Checked here: cap_wasm_admin() re-registers the app tool group before submitting. */
    if (!s_call_lock) {
        snprintf(out, size, "Error: WASM apps are not running");
        return ESP_ERR_INVALID_STATE;
    }
    return cap_wasm_admin(enabled ? CAP_WASM_REQ_ENABLE : CAP_WASM_REQ_DISABLE, name, NULL, out, size);
}
