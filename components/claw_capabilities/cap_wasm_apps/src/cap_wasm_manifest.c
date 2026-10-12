/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_manifest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "cJSON.h"

/* github.com/esp-claw/app-sdk (include/claw.h, tools/manifest_check.py, tools/wasm_check.py) mirrors
 * these manifest rules; update it together with this file. */

bool cap_wasm_name_valid(const char *name, size_t len, size_t max_len)
{
    if (!name || len == 0 || len > max_len || name[0] < 'a' || name[0] > 'z') {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        char c = name[i];

        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    return true;
}

bool cap_wasm_keys_known(const cJSON *obj, const char *const *keys, size_t key_count,
                                const char *where, char *err, size_t err_size)
{
    const cJSON *item = NULL;

    cJSON_ArrayForEach(item, obj) {
        size_t i;

        for (i = 0; i < key_count && strcmp(item->string, keys[i]) != 0; i++) {
        }
        if (i == key_count) {
            snprintf(err, err_size, "unknown %s '%.32s'", where, item->string);
            return false;
        }
    }
    return true;
}

static bool cap_wasm_copy_string(const cJSON *item, const char *field, char *dst, size_t dst_size,
                                 bool required, char *err, size_t err_size)
{
    if (!item) {
        if (required) {
            snprintf(err, err_size, "%s is required", field);
        }
        return !required;
    }
    if (!cJSON_IsString(item) || (required && !item->valuestring[0]) ||
            strlen(item->valuestring) >= dst_size) {
        snprintf(err, err_size, "%s must be a string of %s1-%u bytes", field,
                 required ? "" : "0/", (unsigned)(dst_size - 1));
        return false;
    }
    strcpy(dst, item->valuestring);
    return true;
}

static bool cap_wasm_parse_int(const cJSON *item, const char *field, uint32_t min, uint32_t max,
                               uint32_t *out, char *err, size_t err_size)
{
    if (!item) {
        return true;
    }
    if (!cJSON_IsNumber(item) || item->valuedouble != (double)(int64_t)item->valuedouble ||
            item->valuedouble < min || item->valuedouble > max) {
        snprintf(err, err_size, "%s must be an integer in [%u, %u]", field, (unsigned)min, (unsigned)max);
        return false;
    }
    *out = (uint32_t)item->valuedouble;
    return true;
}

static bool cap_wasm_parse_permissions(const cJSON *perms, cap_wasm_manifest_t *out, char *err, size_t err_size)
{
    static const char *const keys[] = {"log", "kv", "http_profiles", "confirm", "ping", "notify", "timer"};
    static const char *const timer_keys[] = {"min_interval_s"};
    static const struct {
        const char *key;
        uint32_t perm;
    } flags[] = {
        {"log", CAP_WASM_PERM_LOG},
        {"kv", CAP_WASM_PERM_KV},
        {"confirm", CAP_WASM_PERM_CONFIRM},
        {"ping", CAP_WASM_PERM_PING},
        {"notify", CAP_WASM_PERM_NOTIFY},
    };
    const cJSON *profiles = cJSON_GetObjectItemCaseSensitive(perms, "http_profiles");
    const cJSON *timer = cJSON_GetObjectItemCaseSensitive(perms, "timer");
    const cJSON *item = NULL;

    if (!perms) {
        return true;
    }
    if (!cJSON_IsObject(perms)) {
        snprintf(err, err_size, "permissions must be an object");
        return false;
    }
    if (!cap_wasm_keys_known(perms, keys, sizeof(keys) / sizeof(keys[0]), "permission", err, err_size)) {
        return false;
    }
    for (size_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
        item = cJSON_GetObjectItemCaseSensitive(perms, flags[i].key);
        if (item && !cJSON_IsBool(item)) {
            snprintf(err, err_size, "permissions.%s must be a boolean", flags[i].key);
            return false;
        }
        if (cJSON_IsTrue(item)) {
            out->perms |= flags[i].perm;
        }
    }
    if (timer) {
        out->timer_min_s = CAP_WASM_TIMER_MIN_S;
        if (!cJSON_IsObject(timer)) {
            snprintf(err, err_size, "permissions.timer must be an object");
            return false;
        }
        if (!cap_wasm_keys_known(timer, timer_keys, 1, "permissions.timer key", err, err_size) ||
                !cap_wasm_parse_int(cJSON_GetObjectItemCaseSensitive(timer, "min_interval_s"),
                                    "permissions.timer.min_interval_s", CAP_WASM_TIMER_MIN_S, CAP_WASM_TIMER_MAX_S,
                                    &out->timer_min_s, err, err_size)) {
            return false;
        }
        out->perms |= CAP_WASM_PERM_TIMER;
    }
    if (!profiles) {
        return true;
    }
    if (!cJSON_IsArray(profiles) || cJSON_GetArraySize(profiles) == 0 ||
            cJSON_GetArraySize(profiles) > CAP_WASM_MAX_PROFILES) {
        snprintf(err, err_size, "permissions.http_profiles must be an array of 1-%d profile names",
                 CAP_WASM_MAX_PROFILES);
        return false;
    }
    cJSON_ArrayForEach(item, profiles) {
        const char *name = cJSON_GetStringValue(item);
        size_t len = name ? strlen(name) : 0;

        if (len == 0 || len > CAP_WASM_PROFILE_NAME_MAX ||
                strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != len) {
            snprintf(err, err_size, "permissions.http_profiles entries must be profile names "
                     "(1-%d chars of [A-Za-z0-9_-])", CAP_WASM_PROFILE_NAME_MAX);
            return false;
        }
        if (cap_wasm_manifest_allows_profile(out, name)) {
            snprintf(err, err_size, "permissions.http_profiles lists '%s' twice", name);
            return false;
        }
        strcpy(out->http_profiles[out->http_profile_count++], name);
    }
    out->perms |= CAP_WASM_PERM_HTTP;
    return true;
}

static bool cap_wasm_parse_setting(const cJSON *item, cap_wasm_manifest_t *out, char *err, size_t err_size)
{
    static const char *const keys[] = {"key", "type", "default", "secret", "description"};
    static const char *const types[] = {"string", "int", "bool"};
    cap_wasm_setting_t *s = &out->settings[out->setting_count];
    const cJSON *def = cJSON_GetObjectItemCaseSensitive(item, "default");
    const cJSON *secret = cJSON_GetObjectItemCaseSensitive(item, "secret");
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(item, "type"));
    char text[24];
    bool ok;
    size_t t;

    if (!cJSON_IsObject(item)) {
        snprintf(err, err_size, "settings entries must be objects");
        return false;
    }
    if (!cap_wasm_keys_known(item, keys, sizeof(keys) / sizeof(keys[0]), "settings key", err, err_size) ||
            !cap_wasm_copy_string(cJSON_GetObjectItemCaseSensitive(item, "key"), "settings[].key", s->key,
                                  sizeof(s->key), true, err, err_size) ||
            !cap_wasm_copy_string(cJSON_GetObjectItemCaseSensitive(item, "description"), "settings[].description",
                                  s->description, sizeof(s->description), false, err, err_size)) {
        return false;
    }
    if (!cap_wasm_name_valid(s->key, strlen(s->key), CAP_WASM_SETTING_KEY_MAX)) {
        snprintf(err, err_size, "settings key '%s' must be 1-%d chars of [a-z0-9_] starting with a letter", s->key,
                 CAP_WASM_SETTING_KEY_MAX);
        return false;
    }
    if (cap_wasm_manifest_setting(out, s->key, strlen(s->key))) {
        snprintf(err, err_size, "settings lists '%s' twice", s->key);
        return false;
    }
    for (t = 0; type && t < sizeof(types) / sizeof(types[0]) && strcmp(type, types[t]) != 0; t++) {
    }
    if (!type || t == sizeof(types) / sizeof(types[0])) {
        snprintf(err, err_size, "settings '%s': type must be string, int or bool", s->key);
        return false;
    }
    s->type = (uint8_t)t;
    if (secret && !cJSON_IsBool(secret)) {
        snprintf(err, err_size, "settings '%s': secret must be a boolean", s->key);
        return false;
    }
    s->secret = cJSON_IsTrue(secret);
    if (def && s->secret) {
        snprintf(err, err_size, "settings '%s': a secret cannot have a default", s->key);
        return false;
    }
    if (def) {
        if (s->type == CAP_WASM_SETTING_STRING) {
            ok = cJSON_IsString(def) && strlen(def->valuestring) <= CAP_WASM_SETTING_DEFAULT_MAX &&
                 cap_wasm_setting_normalize(s, def->valuestring, s->def, sizeof(s->def));
        } else if (s->type == CAP_WASM_SETTING_INT) {
            ok = cJSON_IsNumber(def) && def->valuedouble >= INT32_MIN && def->valuedouble <= INT32_MAX &&
                 def->valuedouble == (double)(int32_t)def->valuedouble;
            snprintf(text, sizeof(text), "%ld", ok ? (long)def->valuedouble : 0L);
            ok = ok && cap_wasm_setting_normalize(s, text, s->def, sizeof(s->def));
        } else {
            ok = cJSON_IsBool(def);
            snprintf(s->def, sizeof(s->def), "%s", cJSON_IsTrue(def) ? "true" : "false");
        }
        if (!ok) {
            snprintf(err, err_size, "settings '%s': default must be %s", s->key,
                     s->type == CAP_WASM_SETTING_STRING ? "a string of 1-64 bytes" :
                     s->type == CAP_WASM_SETTING_INT ? "an int32" : "a boolean");
            return false;
        }
        s->has_default = true;
    }
    cap_wasm_utf8_sanitize(s->description, strlen(s->description));
    out->setting_count++;
    return true;
}

static bool cap_wasm_parse_settings(const cJSON *settings, cap_wasm_manifest_t *out, char *err, size_t err_size)
{
    const cJSON *item = NULL;

    if (!settings) {
        return true;
    }
    if (!cJSON_IsArray(settings) || cJSON_GetArraySize(settings) > CAP_WASM_MAX_SETTINGS) {
        snprintf(err, err_size, "settings must be an array of at most %d entries", CAP_WASM_MAX_SETTINGS);
        return false;
    }
    cJSON_ArrayForEach(item, settings) {
        if (!cap_wasm_parse_setting(item, out, err, err_size)) {
            return false;
        }
    }
    return true;
}

bool cap_wasm_manifest_parse(const char *json, const char *dir_name, cap_wasm_manifest_t *out,
                             char *err, size_t err_size)
{
    static const char *const keys[] = {"name", "version", "api", "description", "permissions", "limits", "settings"};
    static const char *const limit_keys[] = {"memory_kb", "call_timeout_ms"};
    cJSON *root = cJSON_Parse(json);
    const cJSON *api = cJSON_GetObjectItemCaseSensitive(root, "api");
    const cJSON *limits = NULL;
    uint32_t api_value = 1;
    bool ok = false;

    memset(out, 0, sizeof(*out));
    out->api = 1;
    out->memory_kb = CAP_WASM_MEMORY_KB_DEFAULT;
    out->call_timeout_ms = CAP_WASM_CALL_MS_DEFAULT;

    if (!cJSON_IsObject(root)) {
        snprintf(err, err_size, "manifest.json is not a JSON object");
        goto done;
    }
    if (!cap_wasm_keys_known(root, keys, sizeof(keys) / sizeof(keys[0]), "manifest key", err, err_size) ||
            !cap_wasm_copy_string(cJSON_GetObjectItemCaseSensitive(root, "name"), "name",
                                  out->name, sizeof(out->name), true, err, err_size) ||
            !cap_wasm_copy_string(cJSON_GetObjectItemCaseSensitive(root, "version"), "version",
                                  out->version, sizeof(out->version), true, err, err_size) ||
            !cap_wasm_copy_string(cJSON_GetObjectItemCaseSensitive(root, "description"), "description",
                                  out->description, sizeof(out->description), false, err, err_size)) {
        goto done;
    }
    if (!cap_wasm_name_valid(out->name, strlen(out->name), CAP_WASM_APP_NAME_MAX)) {
        snprintf(err, err_size, "name must be 1-%d chars of [a-z0-9_] starting with a letter",
                 CAP_WASM_APP_NAME_MAX);
        goto done;
    }
    if (dir_name && strcmp(out->name, dir_name) != 0) {
        snprintf(err, err_size, "name '%s' does not match the app directory", out->name);
        goto done;
    }
    cap_wasm_utf8_sanitize(out->description, strlen(out->description));
    if (strspn(out->version, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-+") !=
            strlen(out->version)) {
        snprintf(err, err_size, "version may only contain [A-Za-z0-9.+-]");
        goto done;
    }
    /* Absent in manifests of format 1 packages, which were written for api 1. */
    if (!cap_wasm_parse_int(api, "api", 1, CAP_WASM_API_MAX, &api_value, err, err_size)) {
        goto done;
    }
    out->api = (uint16_t)api_value;
    out->has_api = api != NULL;
    if (!cap_wasm_parse_permissions(cJSON_GetObjectItemCaseSensitive(root, "permissions"), out, err, err_size) ||
            !cap_wasm_parse_settings(cJSON_GetObjectItemCaseSensitive(root, "settings"), out, err, err_size)) {
        goto done;
    }

    limits = cJSON_GetObjectItemCaseSensitive(root, "limits");
    if (limits && !cJSON_IsObject(limits)) {
        snprintf(err, err_size, "limits must be an object");
        goto done;
    }
    if (!cap_wasm_keys_known(limits, limit_keys, sizeof(limit_keys) / sizeof(limit_keys[0]), "limit",
                             err, err_size) ||
            !cap_wasm_parse_int(cJSON_GetObjectItemCaseSensitive(limits, "memory_kb"), "limits.memory_kb",
                                64, CAP_WASM_MEMORY_KB_MAX, &out->memory_kb, err, err_size) ||
            !cap_wasm_parse_int(cJSON_GetObjectItemCaseSensitive(limits, "call_timeout_ms"),
                                "limits.call_timeout_ms", CAP_WASM_CALL_MS_MIN, CAP_WASM_CALL_MS_MAX,
                                &out->call_timeout_ms, err, err_size)) {
        goto done;
    }
    if (out->memory_kb % 64 != 0) {
        snprintf(err, err_size, "limits.memory_kb must be a multiple of 64 (one WASM page)");
        goto done;
    }
    ok = true;

done:
    cJSON_Delete(root);
    return ok;
}

bool cap_wasm_manifest_allows_profile(const cap_wasm_manifest_t *mf, const char *profile)
{
    for (uint32_t i = 0; i < mf->http_profile_count; i++) {
        if (strcmp(mf->http_profiles[i], profile) == 0) {
            return true;
        }
    }
    return false;
}

static const struct {
    uint32_t perm;
    const char *name;
} s_perm_names[] = {
    {CAP_WASM_PERM_LOG, "log"},
    {CAP_WASM_PERM_KV, "kv"},
    {CAP_WASM_PERM_CONFIRM, "confirm"},
    {CAP_WASM_PERM_PING, "ping"},
    {CAP_WASM_PERM_NOTIFY, "notify"},
    {CAP_WASM_PERM_TIMER, "timer"},
};
#define PERM_NAME_COUNT (sizeof(s_perm_names) / sizeof(s_perm_names[0]))

/* Permission `i` of `mf` ("" when that flag is not set); false past the last one. */
static bool perm_at(const cap_wasm_manifest_t *mf, size_t i, char *out, size_t size)
{
    if (i < PERM_NAME_COUNT) {
        snprintf(out, size, "%s", mf->perms & s_perm_names[i].perm ? s_perm_names[i].name : "");
        return true;
    }
    if (i - PERM_NAME_COUNT >= mf->http_profile_count) {
        return false;
    }
    snprintf(out, size, "http: %s", mf->http_profiles[i - PERM_NAME_COUNT]);
    return true;
}

static bool perm_has(const cap_wasm_manifest_t *mf, const char *perm)
{
    char item[CAP_WASM_PROFILE_NAME_MAX + 8];

    for (size_t i = 0; perm_at(mf, i, item, sizeof(item)); i++) {
        if (item[0] && strcmp(item, perm) == 0) {
            return true;
        }
    }
    return false;
}

bool cap_wasm_perms_describe(const cap_wasm_manifest_t *mf, const cap_wasm_manifest_t *old, char *out, size_t size)
{
    char item[CAP_WASM_PROFILE_NAME_MAX + 8];
    bool added_any = false;
    bool removed_any = false;
    size_t len = 0;

    out[0] = '\0';
    for (size_t i = 0; perm_at(mf, i, item, sizeof(item)) && len < size; i++) {
        bool added = item[0] && (!old || !perm_has(old, item));

        if (item[0]) {
            len += snprintf(out + len, size - len, "%s%s%s%s", len ? ", " : "", added && old ? "<b>+" : "", item,
                            added && old ? "</b>" : "");
            added_any |= added;
        }
    }
    if (!len) {
        len = snprintf(out, size, "keine");
    }
    for (size_t i = 0; old && perm_at(old, i, item, sizeof(item)) && len < size; i++) {
        if (item[0] && !perm_has(mf, item)) {
            len += snprintf(out + len, size - len, "%s<s>%s</s>", removed_any ? ", " : "; entfernt: ", item);
            removed_any = true;
        }
    }
    return added_any;
}

void cap_wasm_utf8_sanitize(char *text, size_t len)
{
    size_t i = 0;

    while (i < len) {
        unsigned char c = (unsigned char)text[i];
        size_t n = c < 0x80 ? 1 : (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3 :
                   (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        uint32_t cp = n == 2 ? c & 0x1F : n == 3 ? c & 0x0F : c & 0x07;
        size_t k;

        for (k = 1; n > 1 && k < n && i + k < len && ((unsigned char)text[i + k] & 0xC0) == 0x80; k++) {
            cp = (cp << 6) | ((unsigned char)text[i + k] & 0x3F);
        }
        /* Reject truncated sequences, overlongs, surrogates and code points above U+10FFFF. */
        if (n == 0 || k != n || (n == 3 && (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF))) ||
                (n == 4 && (cp < 0x10000 || cp > 0x10FFFF))) {
            text[i++] = '?';
            continue;
        }
        i += n;
    }
}

static void cap_wasm_namespace(const char *prefix, const char *app_name, char out[CAP_WASM_NVS_NS_LEN])
{
    uint32_t hash = 2166136261u;

    if (strlen(app_name) <= CAP_WASM_NVS_NS_LEN - 4) {
        snprintf(out, CAP_WASM_NVS_NS_LEN, "%s_%s", prefix, app_name);
        return;
    }
    for (const char *p = app_name; *p; p++) {
        hash = (hash ^ (uint8_t)*p) * 16777619u;
    }
    snprintf(out, CAP_WASM_NVS_NS_LEN, "%s-%.4s%08x", prefix, app_name, (unsigned)hash);
}

void cap_wasm_nvs_namespace(const char *app_name, char out[CAP_WASM_NVS_NS_LEN])
{
    cap_wasm_namespace("wa", app_name, out);
}

void cap_wasm_cfg_namespace(const char *app_name, char out[CAP_WASM_NVS_NS_LEN])
{
    cap_wasm_namespace("wc", app_name, out);
}

const cap_wasm_setting_t *cap_wasm_manifest_setting(const cap_wasm_manifest_t *mf, const char *key, size_t key_len)
{
    for (uint32_t i = 0; i < mf->setting_count; i++) {
        if (strlen(mf->settings[i].key) == key_len && memcmp(mf->settings[i].key, key, key_len) == 0) {
            return &mf->settings[i];
        }
    }
    return NULL;
}

const char *cap_wasm_setting_type_name(uint8_t type)
{
    return type == CAP_WASM_SETTING_INT ? "int" : type == CAP_WASM_SETTING_BOOL ? "bool" : "string";
}

bool cap_wasm_setting_normalize(const cap_wasm_setting_t *s, const char *in, char *out, size_t size)
{
    static const char *const yes[] = {"true", "on", "yes", "1"};
    static const char *const no[] = {"false", "off", "no", "0"};
    size_t len = strlen(in);

    if (s->type == CAP_WASM_SETTING_INT) {
        char *end = NULL;
        long long v;

        if (!len || len > 11 || strspn(in, "-0123456789") != len) {
            return false;
        }
        errno = 0;
        v = strtoll(in, &end, 10);
        if (*end || errno || v < INT32_MIN || v > INT32_MAX) {
            return false;
        }
        return snprintf(out, size, "%lld", v) < (int)size;
    }
    if (s->type == CAP_WASM_SETTING_BOOL) {
        for (size_t i = 0; i < sizeof(yes) / sizeof(yes[0]); i++) {
            if (strcasecmp(in, yes[i]) == 0 || strcasecmp(in, no[i]) == 0) {
                return snprintf(out, size, "%s", strcasecmp(in, yes[i]) == 0 ? "true" : "false") < (int)size;
            }
        }
        return false;
    }
    if (!len || len > CAP_WASM_SETTING_VALUE_MAX || len >= size) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)in[i] < 0x20 || in[i] == 0x7F) {
            return false;
        }
    }
    memcpy(out, in, len + 1);
    cap_wasm_utf8_sanitize(out, len);
    return memcmp(out, in, len) == 0;
}
