/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Sandboxed WASM apps (WAMR fast interpreter) loaded from <storage>/apps/<name>/{manifest.json,app.wasm}.
 *
 * Threads: all WAMR calls run on one pthread ("wasm_apps", PSRAM stack; WAMR's ESP-IDF port calls
 * pthread_self()). Requesters (tool calls, /apps, boot) hand it a request, then act as its
 * watchdog: every entry into app code has a wall-clock budget, and when it runs out the requester
 * calls wasm_runtime_terminate(), which WAMR's thread manager turns into a stop at the next
 * branch/call. Time a host function spends blocked (HTTP, Telegram confirmation) is not counted.
 * A trapped or terminated instance is torn down and re-instantiated lazily on the next call;
 * after CAP_WASM_MAX_FAILURES consecutive failures the app is disabled until reload or reboot.
 *
 * Capability groups: "cap_wasm_apps" holds apps_status and the app tools; it is unregistered and
 * re-registered when /apps reload|disable changes the tool set. "cap_wasm_apps_mgr" holds the
 * restricted /apps command handler, which must not live in the group it re-registers.
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

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_GROUP            "cap_wasm_apps"
#define CAP_WASM_MGR_GROUP        "cap_wasm_apps_mgr"
#define CAP_WASM_MAX_APPS         8
#define CAP_WASM_MAX_TOOLS        32   /* dispatch slots, see CAP_WASM_SLOTS */
#define CAP_WASM_MAX_FILE_SIZE    (256 * 1024)
#define CAP_WASM_MANIFEST_MAX     4096
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

typedef enum {
    CAP_WASM_REQ_BOOT,
    CAP_WASM_REQ_CALL,
    CAP_WASM_REQ_RELOAD,
    CAP_WASM_REQ_DISABLE,
    CAP_WASM_REQ_STATUS,
} cap_wasm_req_type_t;

typedef struct {
    cap_wasm_req_type_t type;
    int slot;                             /* CALL */
    const char *arg;                      /* CALL: input JSON; RELOAD/DISABLE: app name; STATUS: "json" */
    const claw_cap_call_context_t *ctx;   /* CALL */
    char *output;
    size_t output_size;
    esp_err_t err;
} cap_wasm_req_t;

static char s_apps_dir[64];
static EXT_RAM_BSS_ATTR cap_wasm_app_t s_apps[CAP_WASM_MAX_APPS];
static size_t s_app_count;
static EXT_RAM_BSS_ATTR cap_wasm_tool_t s_tools[CAP_WASM_MAX_TOOLS];
static size_t s_tool_count;
static EXT_RAM_BSS_ATTR claw_cap_descriptor_t s_descriptors[1 + CAP_WASM_MAX_TOOLS];
static claw_cap_group_t s_group;
static bool s_runtime_ok;

static QueueHandle_t s_req_queue;
static SemaphoreHandle_t s_done;
static SemaphoreHandle_t s_call_lock;

/* The app code currently running on the WASM thread, watched by the requester. */
static struct {
    SemaphoreHandle_t lock;
    wasm_module_inst_t inst;
    int64_t deadline_us;
    int64_t paused_at_us;
    bool terminated;
} s_exec;

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
        /* Re-instantiation after a failure: the registered tool set must not change. */
        return tool && tool->app == app ? tool->local_idx : -CAP_WASM_EPERM;
    }
    if (tool || claw_cap_find(full) || strcmp(full, "apps_status") == 0) {
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
}

static void cap_wasm_unload(cap_wasm_app_t *app)
{
    cap_wasm_teardown(app);
    if (app->module) {
        wasm_runtime_unload(app->module);
        app->module = NULL;
    }
    cap_wasm_remove_tools(app);
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
    fn_init = wasm_runtime_lookup_function(app->inst, "app_init");
    if (!app->env || !app->fn_alloc || !app->fn_call || !fn_init) {
        cap_wasm_set_error(app, "%s", app->env ? "missing export app_init, app_alloc or tool_call" :
                           "cannot create exec env");
        cap_wasm_teardown(app);
        return false;
    }

    app->initializing = true;
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
    app->state = CAP_WASM_APP_READY;
    return true;
}

static bool cap_wasm_check_imports(cap_wasm_app_t *app)
{
    int32_t count = wasm_runtime_get_import_count(app->module);

    for (int32_t i = 0; i < count; i++) {
        wasm_import_t imp;
        uint32_t perm = 0;

        wasm_runtime_get_import_type(app->module, i, &imp);
        if (imp.kind != WASM_IMPORT_EXPORT_KIND_FUNC || strcmp(imp.module_name, "claw") != 0 ||
                !cap_wasm_host_import_perm(imp.name, &perm)) {
            cap_wasm_set_error(app, "imports unknown symbol %s.%s (only claw.* host functions exist)",
                               imp.module_name, imp.name);
            return false;
        }
        if ((app->mf.perms & perm) != perm) {
            cap_wasm_set_error(app, "imports claw.%s but the manifest does not grant that permission", imp.name);
            return false;
        }
        if (!imp.linked) {
            cap_wasm_set_error(app, "claw.%s has the wrong signature (rebuild with apps/sdk/claw.h)", imp.name);
            return false;
        }
    }
    return true;
}

static char *cap_wasm_read_file(const char *path, size_t max_size, size_t *out_size)
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

/* Reads, validates, loads and instantiates one app. `boot` honours the crash marker. */
static void cap_wasm_load(cap_wasm_app_t *app, bool boot)
{
    char path[128];
    char marker[128];
    char err[128];
    char *manifest = NULL;
    char *wasm = NULL;
    size_t size = 0;
    size_t psram_before = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t internal_before = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    int64_t t0 = esp_timer_get_time();
    int64_t t_load;
    FILE *m;
    LoadArgs load_args = {
        .name = app->name,
        .wasm_binary_freeable = true,
    };

    app->state = CAP_WASM_APP_FAILED;
    app->failures = 0;
    app->last_error[0] = '\0';
    snprintf(marker, sizeof(marker), "%s/%s/.loading", s_apps_dir, app->name);
    if (boot && access(marker, F_OK) == 0) {
        cap_wasm_set_error(app, "did not finish loading on a previous boot; /apps reload %s retries", app->name);
        return;
    }

    snprintf(path, sizeof(path), "%s/%s/manifest.json", s_apps_dir, app->name);
    manifest = cap_wasm_read_file(path, CAP_WASM_MANIFEST_MAX, &size);
    if (!manifest) {
        cap_wasm_set_error(app, "manifest.json missing or larger than %d bytes", CAP_WASM_MANIFEST_MAX);
        return;
    }
    if (!cap_wasm_manifest_parse(manifest, app->name, &app->mf, err, sizeof(err))) {
        cap_wasm_set_error(app, "manifest.json: %s", err);
        goto done;
    }
    cap_wasm_nvs_namespace(app->name, app->nvs_ns);

    snprintf(path, sizeof(path), "%s/%s/app.wasm", s_apps_dir, app->name);
    wasm = cap_wasm_read_file(path, CAP_WASM_MAX_FILE_SIZE, &size);
    if (!wasm) {
        cap_wasm_set_error(app, "app.wasm missing or larger than %d KB", CAP_WASM_MAX_FILE_SIZE / 1024);
        goto done;
    }
    /* Module + instance need roughly twice the binary plus the linear memory and stacks. */
    if (psram_before < CAP_WASM_PSRAM_RESERVE + 2 * size + app->mf.memory_kb * 1024 +
            2 * CAP_WASM_EXEC_STACK + CAP_WASM_LOAD_OVERHEAD) {
        cap_wasm_set_error(app, "not enough PSRAM (%u KB free, %u KB must stay free)",
                           (unsigned)(psram_before / 1024), CAP_WASM_PSRAM_RESERVE / 1024);
        goto done;
    }

    m = fopen(marker, "w");
    if (m) {
        fclose(m);
    }
    app->wasm_size = (uint32_t)size;
    app->module = wasm_runtime_load_ex((uint8_t *)wasm, (uint32_t)size, &load_args, err, sizeof(err));
    heap_caps_free(wasm);
    wasm = NULL;
    t_load = esp_timer_get_time();
    if (!app->module) {
        cap_wasm_set_error(app, "load failed: %s", err);
    } else if (!cap_wasm_check_imports(app) || !cap_wasm_instantiate(app)) {
        cap_wasm_unload(app);
    }
    unlink(marker);
    if (app->state != CAP_WASM_APP_READY) {
        goto done;
    }

    app->psram_bytes = (uint32_t)(psram_before - heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
    app->load_ms = (uint32_t)((esp_timer_get_time() - t0) / 1000);
    ESP_LOGI(TAG, "[%s] v%s loaded: %" PRIu32 " B wasm, %u tools, mem cap %" PRIu32 " KB, "
             "load %" PRId64 " ms + init %" PRId64 " ms, psram -%" PRIu32 " B (free %u), internal -%d B",
             app->name, app->mf.version, app->wasm_size,
             (unsigned)cap_wasm_app_tool_count(app),
             app->mf.memory_kb, (t_load - t0) / 1000, (esp_timer_get_time() - t_load) / 1000,
             app->psram_bytes, (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM),
             (int)(internal_before - heap_caps_get_free_size(MALLOC_CAP_INTERNAL)));
    if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) < CAP_WASM_PSRAM_RESERVE) {
        cap_wasm_set_error(app, "unloaded: PSRAM free dropped below %d KB", CAP_WASM_PSRAM_RESERVE / 1024);
        cap_wasm_unload(app);
        app->state = CAP_WASM_APP_FAILED;
    }

done:
    heap_caps_free(manifest);
    heap_caps_free(wasm);
}

static const char *cap_wasm_state_name(cap_wasm_app_state_t state)
{
    switch (state) {
    case CAP_WASM_APP_READY:
        return "ready";
    case CAP_WASM_APP_IDLE:
        return "idle";
    case CAP_WASM_APP_DISABLED:
        return "disabled";
    default:
        return "failed";
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
    if (app->state == CAP_WASM_APP_DISABLED || app->state == CAP_WASM_APP_FAILED) {
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
        app->state = CAP_WASM_APP_IDLE;
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
    return;

failure:
    cap_wasm_teardown(app);
    app->state = CAP_WASM_APP_IDLE;
    if (++app->failures >= CAP_WASM_MAX_FAILURES) {
        app->state = CAP_WASM_APP_DISABLED;
        ESP_LOGE(TAG, "[%s] disabled after %d consecutive failures (last: %s); /apps reload %s re-enables it",
                 app->name, CAP_WASM_MAX_FAILURES, app->last_error, app->name);
    } else {
        ESP_LOGW(TAG, "[%s] failure %u/%d: %s", app->name, app->failures, CAP_WASM_MAX_FAILURES, app->last_error);
    }
}

static void cap_wasm_render_status(char *out, size_t size, bool json)
{
    cJSON *list = json ? cJSON_CreateArray() : NULL;
    size_t len = 0;
    char *rendered;

    out[0] = '\0';
    if (!json && s_app_count == 0) {
        snprintf(out, size, "No WASM apps. Upload to %s/<name>/{manifest.json,app.wasm}, then /apps reload <name>.",
                 s_apps_dir);
        return;
    }
    for (size_t i = 0; i < s_app_count; i++) {
        cap_wasm_app_t *app = &s_apps[i];
        wasm_memory_inst_t mem = app->inst ? wasm_runtime_get_default_memory(app->inst) : NULL;
        uint32_t mem_kb = mem ? (uint32_t)(wasm_memory_get_cur_page_count(mem) * 64) : 0;

        if (json) {
            cJSON *item = cJSON_CreateObject();
            cJSON *tools = cJSON_AddArrayToObject(item, "tools");

            cJSON_AddStringToObject(item, "name", app->name);
            cJSON_AddStringToObject(item, "version", app->mf.version);
            cJSON_AddStringToObject(item, "state", cap_wasm_state_name(app->state));
            cJSON_AddStringToObject(item, "description", app->mf.description);
            for (size_t t = 0; t < s_tool_count; t++) {
                if (s_tools[t].app == app) {
                    cJSON_AddItemToArray(tools, cJSON_CreateString(s_tools[t].name));
                }
            }
            cJSON_AddNumberToObject(item, "memory_kb", mem_kb);
            cJSON_AddNumberToObject(item, "memory_cap_kb", app->mf.memory_kb);
            cJSON_AddNumberToObject(item, "psram_kb", app->psram_bytes / 1024);
            cJSON_AddNumberToObject(item, "calls", app->calls);
            cJSON_AddNumberToObject(item, "failures", app->failures);
            if (app->last_error[0]) {
                cJSON_AddStringToObject(item, "last_error", app->last_error);
            }
            cJSON_AddItemToArray(list, item);
            continue;
        }
        len += snprintf(out + len, len < size ? size - len : 0,
                        "%s`%s` %s — %s, mem %" PRIu32 "/%" PRIu32 " KB, psram %" PRIu32 " KB, calls %" PRIu32 "\n",
                        i ? "\n" : "", app->name, app->mf.version[0] ? app->mf.version : "?",
                        cap_wasm_state_name(app->state), mem_kb, app->mf.memory_kb,
                        app->psram_bytes / 1024, app->calls);
        for (size_t t = 0; t < s_tool_count; t++) {
            if (s_tools[t].app == app) {
                len += snprintf(out + len, len < size ? size - len : 0, "  tool `%s`\n", s_tools[t].name);
            }
        }
        if (app->last_error[0]) {
            len += snprintf(out + len, len < size ? size - len : 0, "  last error: %s\n", app->last_error);
        }
    }
    if (json) {
        rendered = list ? cJSON_PrintUnformatted(list) : NULL;
        snprintf(out, size, "%s", rendered ? rendered : "Error: out of memory");
        free(rendered);
        cJSON_Delete(list);
    }
}

static cap_wasm_app_t *cap_wasm_find_app(const char *name)
{
    for (size_t i = 0; i < s_app_count; i++) {
        if (strcmp(s_apps[i].name, name) == 0) {
            return &s_apps[i];
        }
    }
    return NULL;
}

/* Adds a slot for a directory name; NULL when invalid or full. */
static cap_wasm_app_t *cap_wasm_add_app(const char *name)
{
    cap_wasm_app_t *app;

    if (!cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX)) {
        ESP_LOGW(TAG, "ignoring %s/%s: app names are 1-%d chars of [a-z0-9_] starting with a letter",
                 s_apps_dir, name, CAP_WASM_APP_NAME_MAX);
        return NULL;
    }
    if (s_app_count >= CAP_WASM_MAX_APPS) {
        ESP_LOGW(TAG, "ignoring %s/%s: at most %d apps", s_apps_dir, name, CAP_WASM_MAX_APPS);
        return NULL;
    }
    app = &s_apps[s_app_count++];
    memset(app, 0, sizeof(*app));
    strlcpy(app->name, name, sizeof(app->name));
    return app;
}

static void cap_wasm_do_boot(void)
{
    DIR *dir = opendir(s_apps_dir);
    struct dirent *ent;

    if (!dir) {
        ESP_LOGI(TAG, "no %s directory, no WASM apps", s_apps_dir);
        return;
    }
    while ((ent = readdir(dir)) != NULL) {
        cap_wasm_app_t *app;

        if (ent->d_name[0] == '.' || ent->d_type != DT_DIR || !(app = cap_wasm_add_app(ent->d_name))) {
            continue;
        }
        cap_wasm_load(app, true);
    }
    closedir(dir);
}

static void cap_wasm_do_admin(cap_wasm_req_t *req)
{
    cap_wasm_app_t *app = cap_wasm_find_app(req->arg);
    char path[96];
    struct stat st;

    req->err = ESP_OK;
    if (req->type == CAP_WASM_REQ_RELOAD && !app) {
        snprintf(path, sizeof(path), "%s/%s", s_apps_dir, req->arg);
        app = stat(path, &st) == 0 && S_ISDIR(st.st_mode) ? cap_wasm_add_app(req->arg) : NULL;
    }
    if (!app) {
        snprintf(req->output, req->output_size, "No WASM app '%s'.", req->arg);
        req->err = ESP_ERR_NOT_FOUND;
        return;
    }
    cap_wasm_unload(app);
    if (req->type == CAP_WASM_REQ_DISABLE) {
        app->state = CAP_WASM_APP_DISABLED;
        snprintf(app->last_error, sizeof(app->last_error), "disabled by /apps disable");
        snprintf(req->output, req->output_size, "Disabled `%s` until /apps reload %s or reboot.", app->name, app->name);
        return;
    }
    cap_wasm_load(app, false);
    if (app->state == CAP_WASM_APP_READY) {
        snprintf(req->output, req->output_size, "Reloaded `%s` %s: %u tools.", app->name, app->mf.version,
                 (unsigned)cap_wasm_app_tool_count(app));
    } else {
        snprintf(req->output, req->output_size, "Failed to load `%s`: %s", app->name, app->last_error);
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
    while (xQueueReceive(s_req_queue, &req, portMAX_DELAY) == pdTRUE) {
        if (!s_runtime_ok) {
            snprintf(req->output, req->output_size, "Error: WASM runtime failed to start");
            req->err = ESP_ERR_INVALID_STATE;
        } else if (req->type == CAP_WASM_REQ_BOOT) {
            cap_wasm_do_boot();
        } else if (req->type == CAP_WASM_REQ_CALL) {
            cap_wasm_do_call(req);
        } else if (req->type == CAP_WASM_REQ_STATUS) {
            cap_wasm_render_status(req->output, req->output_size, req->arg != NULL);
            req->err = ESP_OK;
        } else {
            cap_wasm_do_admin(req);
        }
        xSemaphoreGive(s_done);
    }
    return NULL;
}

/* Hands a request to the WASM thread and watches its budget until it is done. */
static esp_err_t cap_wasm_submit(cap_wasm_req_t *req, TickType_t lock_wait)
{
    if (!s_call_lock || xSemaphoreTake(s_call_lock, lock_wait) != pdTRUE) {
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

static esp_err_t cap_wasm_status_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    cap_wasm_req_t req = {
        .type = CAP_WASM_REQ_STATUS,
        .arg = "json",
        .output = output,
        .output_size = output_size,
    };

    (void)input_json;
    (void)ctx;
    return cap_wasm_submit(&req, pdMS_TO_TICKS(CAP_WASM_STATUS_WAIT_MS));
}

/* (Re-)registers the cap_wasm_apps group with apps_status and the current tools. */
static void cap_wasm_publish_tools(void)
{
    s_descriptors[0] = (claw_cap_descriptor_t) {
        .id = "apps_status",
        .name = "apps_status",
        .family = "wasm_app",
        .description = "List installed WASM apps with version, state, tools, memory use and last error.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_wasm_status_execute,
    };
    for (size_t i = 0; i < s_tool_count; i++) {
        s_descriptors[1 + i] = (claw_cap_descriptor_t) {
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
        .descriptor_count = 1 + s_tool_count,
    };
    if (claw_cap_register_group(&s_group) != ESP_OK) {
        ESP_LOGE(TAG, "failed to register the %s group", CAP_WASM_GROUP);
    }
}

/* /apps reload|disable <name>: the tool set may change, so the group is drained and re-registered. */
static esp_err_t cap_wasm_admin(cap_wasm_req_type_t type, const char *name, char *output, size_t output_size)
{
    cap_wasm_req_t req = {
        .type = type,
        .arg = name,
        .output = output,
        .output_size = output_size,
    };
    esp_err_t err = claw_cap_unregister_group(CAP_WASM_GROUP, CAP_WASM_DRAIN_MS);

    if (err == ESP_ERR_TIMEOUT) {
        claw_cap_enable_group(CAP_WASM_GROUP);
        snprintf(output, output_size, "A WASM app call is still running, try again.");
        return err;
    }
    err = cap_wasm_submit(&req, portMAX_DELAY);
    cap_wasm_publish_tools();
    return err;
}

static esp_err_t cap_wasm_command_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                          char *output, size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    const char *command = cJSON_GetStringValue(cJSON_GetObjectItem(input, "command"));
    char verb[16] = "";
    char name[CAP_WASM_APP_NAME_MAX + 2] = "";
    esp_err_t err = ESP_OK;

    (void)ctx;
    if (command) {
        sscanf(command, "%15s %25s", verb, name);
    }
    if (!verb[0] || strcmp(verb, "list") == 0) {
        cap_wasm_req_t req = {
            .type = CAP_WASM_REQ_STATUS,
            .output = output,
            .output_size = output_size,
        };

        err = cap_wasm_submit(&req, pdMS_TO_TICKS(CAP_WASM_STATUS_WAIT_MS));
    } else if (name[0] && strlen(name) <= CAP_WASM_APP_NAME_MAX &&
               (strcmp(verb, "reload") == 0 || strcmp(verb, "disable") == 0)) {
        err = cap_wasm_admin(verb[0] == 'r' ? CAP_WASM_REQ_RELOAD : CAP_WASM_REQ_DISABLE, name,
                             output, output_size);
    } else {
        snprintf(output, output_size,
                 "Usage:\n/apps  List WASM apps\n/apps reload <name>  (Re)load an app from %s/<name>/\n"
                 "/apps disable <name>  Unload an app until reload or reboot", s_apps_dir);
    }
    cJSON_Delete(input);
    return err;
}

static const claw_cap_descriptor_t s_mgr_descriptors[] = {
    {
        .id = "apps_command",
        .name = "apps_command",
        .family = "wasm_app",
        .description = "Handle the /apps chat command.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = cap_wasm_command_execute,
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
    if (claw_cap_group_exists(CAP_WASM_GROUP)) {
        return ESP_OK;
    }
    snprintf(s_apps_dir, sizeof(s_apps_dir), "%s/apps", base_path);

    /* Failures below are logged but never fail boot (app_claw_start would abort). */
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
    if (claw_cap_register_group(&s_mgr_group) != ESP_OK) {
        ESP_LOGE(TAG, "failed to register the %s group", CAP_WASM_MGR_GROUP);
    }
    cap_wasm_publish_tools();
    return ESP_OK;
}
