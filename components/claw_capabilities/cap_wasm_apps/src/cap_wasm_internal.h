/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Shared between the runtime (cap_wasm_apps.c) and the host API (cap_wasm_host.c). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cap_wasm_manifest.h"
#include "cap_wasm_pkg.h"
#include "claw_cap.h"
#include "wasm_export.h"

#define CAP_WASM_PSRAM_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)

/* Host API error codes (returned negated). Must match apps/sdk/claw.h. */
enum {
    CAP_WASM_EPERM = 1,
    CAP_WASM_ENOENT = 2,
    CAP_WASM_EIO = 5,
    CAP_WASM_E2BIG = 7,
    CAP_WASM_ENOMEM = 12,
    CAP_WASM_EEXIST = 17,
    CAP_WASM_EINVAL = 22,
    CAP_WASM_ENOSPC = 28,
    CAP_WASM_ENOTSUP = 95,
    CAP_WASM_ENOBUFS = 105,
    CAP_WASM_ETIMEDOUT = 110,
    CAP_WASM_ECANCELED = 125,
};

typedef enum {
    CAP_WASM_APP_FAILED = 0, /* cannot load, see last_error; no tools registered */
    CAP_WASM_APP_LOADED,     /* module in memory; inst NULL means re-instantiate on the next call */
    CAP_WASM_APP_UNLOADED,   /* verified, tools registered, loaded on the next call */
    CAP_WASM_APP_DISABLED,   /* by /apps disable (persisted) or after repeated failures (until reload/reboot) */
    CAP_WASM_APP_UNSIGNED,   /* no valid signature by a trusted key and app_allow_unsigned is off */
} cap_wasm_app_state_t;

typedef struct {
    char name[CAP_WASM_APP_NAME_MAX + 1];
    cap_wasm_manifest_t mf;
    char nvs_ns[CAP_WASM_NVS_NS_LEN];
    cap_wasm_app_state_t state;
    wasm_module_t module;
    wasm_module_inst_t inst;
    wasm_exec_env_t env;
    wasm_function_inst_t fn_alloc;
    wasm_function_inst_t fn_call;
    bool initializing;  /* inside app_init(): tool_register allowed */
    bool tools_frozen;  /* tools already registered: tool_register must name existing tools */
    bool tools_changed; /* a frozen app_init registered a different tool set */
    uint8_t init_tools; /* existing tools named by the current frozen app_init */
    bool enabled;       /* persisted in index.json */
    uint32_t installed_at;
    char key_id[9];     /* signing key, "" when unsigned */
    char wasm_sha256[65];
    char source_url[256]; /* where it was installed from, for /app update */
    int64_t last_used_us; /* last call or load, for idle unload and LRU eviction */
    uint32_t wasm_size;
    uint32_t psram_bytes;
    uint32_t load_ms;
    uint32_t calls;
    uint8_t failures;   /* consecutive traps/timeouts */
    char last_error[128];
} cap_wasm_app_t;

typedef struct {
    cap_wasm_app_t *app;
    int32_t local_idx;  /* passed to the app's tool_call() */
    char *name;         /* "<app>_<tool>" */
    char *desc;
    char *schema;
} cap_wasm_tool_t;

/* State of the tool call running on the WASM thread (one at a time). */
typedef struct {
    cap_wasm_app_t *app;
    const claw_cap_call_context_t *ctx;
    char *output;
    size_t output_size;
    bool result_set;
    uint32_t logs;
    uint32_t kv_writes;
    char *resp;         /* last http_profile_request response body or error text */
    size_t resp_len;
    size_t resp_off;
} cap_wasm_call_t;

extern cap_wasm_call_t g_cap_wasm_call;
extern NativeSymbol g_cap_wasm_natives[];
extern const size_t g_cap_wasm_native_count;

/* Permission a "claw" import needs (0 = always allowed); false for unknown imports. */
bool cap_wasm_host_import_perm(const char *name, uint32_t *out_perm);

/* Registers a tool for the app being initialised; returns its local index or -errno. */
int32_t cap_wasm_tool_add(cap_wasm_app_t *app, const char *name, uint32_t name_len,
                          const char *desc, uint32_t desc_len, const char *schema, uint32_t schema_len);

/* Stops the call budget clock while a host function blocks (HTTP, confirmation). */
void cap_wasm_budget_pause(bool pause);

/* ---------- Runtime <-> installer (cap_wasm_install.c) ---------- */

typedef enum {
    CAP_WASM_REQ_BOOT,
    CAP_WASM_REQ_CALL,
    CAP_WASM_REQ_STATUS,
    CAP_WASM_REQ_LOAD,
    CAP_WASM_REQ_UNLOAD,
    /* The requests below can change the tool set. */
    CAP_WASM_REQ_RELOAD,
    CAP_WASM_REQ_ENABLE,
    CAP_WASM_REQ_DISABLE,
    CAP_WASM_REQ_INSTALL,  /* swaps <name>.new/ in; `extra` is the source URL */
    CAP_WASM_REQ_REMOVE,
} cap_wasm_req_type_t;

extern char g_cap_wasm_apps_dir[64];
extern cap_wasm_key_t g_cap_wasm_trusted[CAP_WASM_MAX_TRUSTED];
extern size_t g_cap_wasm_trusted_count;

/* Whole file in PSRAM, NUL-terminated; NULL when missing, empty or larger than max_size. */
char *cap_wasm_read_file(const char *path, size_t max_size, size_t *out_size);
bool cap_wasm_write_file(const char *path, const char *data, size_t len);
/* Deletes an app directory (app directories hold only files); true when it is gone. */
bool cap_wasm_rmdir(const char *path);

/* Runs a request for app `name` on the WASM thread; re-registers the app tools when needed. */
esp_err_t cap_wasm_admin(cap_wasm_req_type_t type, const char *name, const char *extra,
                         char *output, size_t output_size);

/* Telegram chat to confirm in for `ctx`, or NULL when it does not come from an allowed chat. */
const char *cap_wasm_confirm_chat(const claw_cap_call_context_t *ctx);

/*
 * Downloads an .ecapp from an https URL, verifies it, asks for confirmation in the Telegram chat
 * of `ctx` and installs it. `expect_name` (update) must match the package; an older version than
 * the installed one needs `force`. Must not run on the WASM thread or the Telegram poll task.
 */
esp_err_t cap_wasm_install(const char *url, const char *expect_name, bool force,
                           const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* Asks for confirmation, then deletes the app, its files and its key-value data. */
esp_err_t cap_wasm_remove(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* Runs "/app install|update|remove ..." on its own task and sends the result to `chat_id`. */
esp_err_t cap_wasm_start_job(const char *command, const char *chat_id);
