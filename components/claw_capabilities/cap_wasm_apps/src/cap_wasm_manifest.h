/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/* Manifest and name rules for WASM apps. Pure C + cJSON so it can be unit-tested on the host. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CAP_WASM_APP_NAME_MAX      24  /* [a-z][a-z0-9_]* */
#define CAP_WASM_TOOL_NAME_MAX     48  /* "<app>_<tool>" */
#define CAP_WASM_VERSION_MAX       16
#define CAP_WASM_DESC_MAX          200
#define CAP_WASM_PROFILE_NAME_MAX  31
#define CAP_WASM_MAX_PROFILES      4
#define CAP_WASM_NVS_NS_LEN        16  /* NVS namespace incl. NUL */

#define CAP_WASM_MEMORY_KB_DEFAULT 64
#define CAP_WASM_MEMORY_KB_MAX     512
#define CAP_WASM_CALL_MS_DEFAULT   5000
#define CAP_WASM_CALL_MS_MIN       100
#define CAP_WASM_CALL_MS_MAX       30000

#define CAP_WASM_MAX_SETTINGS        8
#define CAP_WASM_SETTING_KEY_MAX     15  /* NVS key limit; [a-z][a-z0-9_]* */
#define CAP_WASM_SETTING_VALUE_MAX   256 /* value set with /app config */
#define CAP_WASM_SETTING_DEFAULT_MAX 64  /* manifest default (normalized text) */
#define CAP_WASM_SETTING_DESC_MAX    100

typedef enum {
    CAP_WASM_PERM_LOG = 1 << 0,
    CAP_WASM_PERM_KV = 1 << 1,
    CAP_WASM_PERM_HTTP = 1 << 2,
    CAP_WASM_PERM_CONFIRM = 1 << 3,
    CAP_WASM_PERM_PING = 1 << 4,
} cap_wasm_perm_t;

typedef enum {
    CAP_WASM_SETTING_STRING = 0,
    CAP_WASM_SETTING_INT,
    CAP_WASM_SETTING_BOOL,
} cap_wasm_setting_type_t;

/* One entry of manifest "settings"; values are kept as text ("42", "true"). */
typedef struct {
    char key[CAP_WASM_SETTING_KEY_MAX + 1];
    uint8_t type;      /* cap_wasm_setting_type_t */
    bool secret;       /* never shown to the LLM, masked in /app config; no default allowed */
    bool has_default;
    char def[CAP_WASM_SETTING_DEFAULT_MAX + 1];
    char description[CAP_WASM_SETTING_DESC_MAX + 1];
} cap_wasm_setting_t;

typedef struct {
    char name[CAP_WASM_APP_NAME_MAX + 1];
    char version[CAP_WASM_VERSION_MAX + 1];
    char description[CAP_WASM_DESC_MAX + 1];
    uint32_t perms;
    char http_profiles[CAP_WASM_MAX_PROFILES][CAP_WASM_PROFILE_NAME_MAX + 1];
    uint32_t http_profile_count;
    uint32_t memory_kb;
    uint32_t call_timeout_ms;
    cap_wasm_setting_t settings[CAP_WASM_MAX_SETTINGS];
    uint32_t setting_count;
} cap_wasm_manifest_t;

/* True for 1..max_len bytes of [a-z0-9_] starting with a letter. */
bool cap_wasm_name_valid(const char *name, size_t len, size_t max_len);

/*
 * Parses and strictly validates manifest.json. `dir_name` is the app directory, which must equal
 * the manifest name (NULL skips that check). Unknown keys or permissions reject the manifest. On
 * failure `err` says why.
 */
bool cap_wasm_manifest_parse(const char *json, const char *dir_name, cap_wasm_manifest_t *out,
                             char *err, size_t err_size);

struct cJSON;

/* False (with `err` naming the key) when `obj` has a key that is not in `keys`. */
bool cap_wasm_keys_known(const struct cJSON *obj, const char *const *keys, size_t key_count,
                         const char *where, char *err, size_t err_size);

bool cap_wasm_manifest_allows_profile(const cap_wasm_manifest_t *mf, const char *profile);

/*
 * Lists the permissions of `mf` ("log, kv, http: <profile>", "keine" when none) for a Telegram
 * HTML confirmation. With `old` (the installed manifest), permissions it lacks are shown as
 * <b>+name</b> and the ones only it has are appended as "; entfernt: <s>name</s>". True when `mf`
 * has a permission `old` lacks (any permission when `old` is NULL).
 */
bool cap_wasm_perms_describe(const cap_wasm_manifest_t *mf, const cap_wasm_manifest_t *old, char *out, size_t size);

/* Replaces every byte that is not part of a valid UTF-8 sequence with '?', so app-supplied text
 * cannot make the JSON sent to the LLM provider invalid. */
void cap_wasm_utf8_sanitize(char *text, size_t len);

/*
 * Per-app NVS namespace (max 15 chars): "wa_<name>" when the name has at most 12 chars, else
 * "wa-" + first 4 chars + 8 hex digits of FNV-1a(name). '-' never occurs in app names, so the
 * two forms cannot collide.
 */
void cap_wasm_nvs_namespace(const char *app_name, char out[CAP_WASM_NVS_NS_LEN]);

/* Namespace of the app's settings and timer state: as above with "wc" instead of "wa". */
void cap_wasm_cfg_namespace(const char *app_name, char out[CAP_WASM_NVS_NS_LEN]);

/* The declared setting `key` (key_len bytes, not NUL-terminated), or NULL. */
const cap_wasm_setting_t *cap_wasm_manifest_setting(const cap_wasm_manifest_t *mf, const char *key, size_t key_len);

const char *cap_wasm_setting_type_name(uint8_t type);

/*
 * Checks `in` against the setting's type and writes its stored form to `out`: strings as given
 * (1-CAP_WASM_SETTING_VALUE_MAX bytes of valid UTF-8 without control characters), ints as int32
 * decimal, bools as "true"/"false" (accepts true/false, on/off, yes/no, 1/0). False when invalid.
 */
bool cap_wasm_setting_normalize(const cap_wasm_setting_t *s, const char *in, char *out, size_t size);
