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
    CAP_WASM_APP_FAILED = 0, /* not loaded, see last_error */
    CAP_WASM_APP_READY,      /* module loaded and instantiated */
    CAP_WASM_APP_IDLE,       /* module loaded, instance torn down; re-instantiated on next call */
    CAP_WASM_APP_DISABLED,   /* by /apps disable or after repeated failures, until reload/reboot */
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
    bool tools_frozen;  /* re-instantiation: tool_register must name existing tools */
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
