/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_manifest.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"

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

static bool cap_wasm_keys_known(const cJSON *obj, const char *const *keys, size_t key_count,
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
    static const char *const keys[] = {"log", "kv", "http_profiles", "confirm"};
    static const struct {
        const char *key;
        uint32_t perm;
    } flags[] = {
        {"log", CAP_WASM_PERM_LOG},
        {"kv", CAP_WASM_PERM_KV},
        {"confirm", CAP_WASM_PERM_CONFIRM},
    };
    const cJSON *profiles = cJSON_GetObjectItemCaseSensitive(perms, "http_profiles");
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

bool cap_wasm_manifest_parse(const char *json, const char *dir_name, cap_wasm_manifest_t *out,
                             char *err, size_t err_size)
{
    static const char *const keys[] = {"name", "version", "description", "permissions", "limits"};
    static const char *const limit_keys[] = {"memory_kb", "call_timeout_ms"};
    cJSON *root = cJSON_Parse(json);
    const cJSON *limits = NULL;
    bool ok = false;

    memset(out, 0, sizeof(*out));
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
    if (strcmp(out->name, dir_name) != 0) {
        snprintf(err, err_size, "name '%s' does not match the app directory", out->name);
        goto done;
    }
    cap_wasm_utf8_sanitize(out->description, strlen(out->description));
    if (strspn(out->version, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-+") !=
            strlen(out->version)) {
        snprintf(err, err_size, "version may only contain [A-Za-z0-9.+-]");
        goto done;
    }
    if (!cap_wasm_parse_permissions(cJSON_GetObjectItemCaseSensitive(root, "permissions"), out, err, err_size)) {
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

void cap_wasm_nvs_namespace(const char *app_name, char out[CAP_WASM_NVS_NS_LEN])
{
    uint32_t hash = 2166136261u;

    if (strlen(app_name) <= CAP_WASM_NVS_NS_LEN - 4) {
        snprintf(out, CAP_WASM_NVS_NS_LEN, "wa_%s", app_name);
        return;
    }
    for (const char *p = app_name; *p; p++) {
        hash = (hash ^ (uint8_t)*p) * 16777619u;
    }
    snprintf(out, CAP_WASM_NVS_NS_LEN, "wa-%.4s%08x", app_name, (unsigned)hash);
}
