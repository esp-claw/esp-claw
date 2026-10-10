/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Shared between the runtime (cap_wasm_apps.c) and the host API (cap_wasm_host.c). */

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cap_wasm_manifest.h"
#include "cap_im_tg.h"
#include "cap_wasm_pkg.h"
#include "cap_wasm_release.h"
#include "claw_cap.h"
#include "wasm_export.h"

#define CAP_WASM_PSRAM_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#define CAP_WASM_MAX_APPS   8

/* Host API error codes (returned negated). Must match include/claw.h of github.com/esp-claw/app-sdk. */
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

/* Held by an app install and by a firmware update, which must not run at the same time. */
extern atomic_flag g_cap_wasm_busy;

/* Takes a chunk of a streamed download; false aborts the download. */
typedef bool (*cap_wasm_sink_t)(void *ctx, const uint8_t *data, size_t len);

/*
 * https GET following at most 5 https redirects (no auth sent, queries not logged). download
 * returns the body (at most `max` bytes plus a NUL, PSRAM, caller frees), stream hands it to `sink`
 * in chunks.
 */
uint8_t *cap_wasm_download(const char *url, size_t max, size_t *out_len, char *err, size_t err_size);
esp_err_t cap_wasm_stream(const char *url, cap_wasm_sink_t sink, void *ctx, char *err, size_t err_size);

/*
 * Streams https://api.github.com/repos/<repo>/releases/latest through `scan` (set up by the
 * caller); false with `err` set when the request fails (403: rate limit, 404: no release).
 */
bool cap_wasm_release_latest(const char *repo, cap_wasm_rel_scan_t *scan, char *err, size_t err_size);

/* Parsed manifest of installed app `name`; false when it is missing or invalid. */
bool cap_wasm_installed_manifest(const char *name, cap_wasm_manifest_t *mf);

/* Shows `html` with a confirm and a cancel button in `chat`; ESP_OK when confirmed. */
esp_err_t cap_wasm_ask(const char *chat, char *html, size_t html_size, const char *yes_label);

/* Whole file in PSRAM, NUL-terminated; NULL when missing, empty or larger than max_size. */
char *cap_wasm_read_file(const char *path, size_t max_size, size_t *out_size);
bool cap_wasm_write_file(const char *path, const char *data, size_t len);
/* Deletes an app directory (app directories hold only files); true when it is gone. */
bool cap_wasm_rmdir(const char *path);

/* Runs a request for app `name` on the WASM thread; re-registers the app tools when needed. */
esp_err_t cap_wasm_admin(cap_wasm_req_type_t type, const char *name, const char *extra,
                         char *output, size_t output_size);


/*
 * Downloads an .ecapp from an https URL, verifies it, asks for confirmation in the Telegram chat
 * of `ctx` and installs it. `expect_name` (update) must match the package; an older version than
 * the installed one needs `force`. `confirmed` (the update was confirmed in a list) skips the
 * question unless the new version adds permissions. Must not run on the WASM thread or the
 * Telegram poll task.
 */
esp_err_t cap_wasm_install(const char *url, const char *expect_name, bool force, bool confirmed,
                           const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* Asks for confirmation, then deletes the app, its files and its key-value data. */
esp_err_t cap_wasm_remove(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* ---------- Update checks (cap_wasm_updates.c); they block on HTTP, not on the poll task ---------- */

/* "/app updates": every app and the firmware with installed and available versions. */
esp_err_t cap_wasm_check_updates(char *output, size_t output_size);

/* "/app update <name>": installs the latest GitHub release of the app's source (or the source URL itself). */
esp_err_t cap_wasm_update(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* "/app update all": one confirmation for every app update, then installs them in turn until one fails. */
esp_err_t cap_wasm_update_all(const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* Starts the daily and boot update checks when update_check_time is set. */
void cap_wasm_updates_start(void);

/* Tool handlers in the cap_wasm_apps_mgr group. */
esp_err_t cap_wasm_check_updates_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size);
esp_err_t cap_wasm_update_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                  char *output, size_t output_size);

/*
 * Runs "/app install|update|updates|remove ..." (or "fw <args>" for cap_wasm_fw_command) on its own task
 * and sends the result to `chat_id`.
 */
esp_err_t cap_wasm_start_job(const char *command, const char *chat_id);

/* ---------- Firmware updates (cap_wasm_fw.c) ---------- */

/* "/fw" arguments: "" (status), "check [url]" or "update [--force] [url]". Blocks; not on the poll task. */
esp_err_t cap_wasm_fw_command(const char *args, const claw_cap_call_context_t *ctx, char *output, size_t output_size);

/* Signed version of the latest firmware release and how it compares to the running one. */
bool cap_wasm_fw_latest(char version[CAP_WASM_FW_TEXT_MAX + 1], int *cmp, char *err, size_t err_size);

/* Starts the post-update health check / rollback report when there is something to do. */
void cap_wasm_fw_boot(void);

/* Tool handlers in the cap_wasm_apps_mgr group. */
esp_err_t cap_wasm_fw_command_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                      char *output, size_t output_size);
esp_err_t cap_wasm_fw_status_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                     char *output, size_t output_size);
esp_err_t cap_wasm_fw_check_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                    char *output, size_t output_size);
esp_err_t cap_wasm_fw_update_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                     char *output, size_t output_size);
