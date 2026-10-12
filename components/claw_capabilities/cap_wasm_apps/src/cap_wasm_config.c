/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Per-app settings declared in manifest "settings": one NVS namespace per app
 * (cap_wasm_cfg_namespace()), one string entry per set key. The user sets values with
 * "/app config" in Telegram; apps read them with claw_config_get(); the LLM only gets a listing
 * with secret values left out. Keys starting with '_' are firmware state, not settings. Runs on
 * the WASM thread (s_apps is only touched there).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cap_wasm_apps.h"
#include "cap_wasm_internal.h"
#include "esp_log.h"
#include "nvs.h"

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_CFG_KEYS_MAX 24 /* NVS entries looked at when pruning */
#define CAP_WASM_CFG_RESET_ARG "--reset"

int32_t cap_wasm_cfg_get(const cap_wasm_app_t *app, const cap_wasm_setting_t *s, char *out, size_t size,
                         bool *is_default)
{
    char ns[CAP_WASM_NVS_NS_LEN];
    nvs_handle_t h;
    size_t len = size;
    esp_err_t err;

    *is_default = false;
    cap_wasm_cfg_namespace(app->name, ns);
    err = nvs_open(ns, NVS_READONLY, &h);
    if (err == ESP_OK) {
        err = nvs_get_str(h, s->key, out, &len);
        nvs_close(h);
    }
    if (err == ESP_OK) {
        return (int32_t)strlen(out);
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) {
        return err == ESP_ERR_NVS_INVALID_LENGTH ? -CAP_WASM_ENOBUFS : -CAP_WASM_EIO;
    }
    if (!s->has_default) {
        return -CAP_WASM_ENOENT;
    }
    *is_default = true;
    return snprintf(out, size, "%s", s->def) < (int)size ? (int32_t)strlen(out) : -CAP_WASM_ENOBUFS;
}

/* Value for a Telegram reply inside `code`: backticks would end the code span. */
static void cap_wasm_cfg_display(const char *value, char *out, size_t size)
{
    snprintf(out, size, "%s", value);
    for (char *p = out; *p; p++) {
        *p = *p == '`' ? '\'' : *p;
    }
}

static esp_err_t cap_wasm_cfg_list(const cap_wasm_app_t *app, bool json, char *out, size_t size)
{
    char value[CAP_WASM_SETTING_VALUE_MAX + 1];
    char shown[CAP_WASM_SETTING_VALUE_MAX + 1];
    cJSON *root = json ? cJSON_CreateObject() : NULL;
    cJSON *list = json ? cJSON_AddArrayToObject(root, "settings") : NULL;
    size_t len = 0;
    char *rendered;

    if (json) {
        cJSON_AddStringToObject(root, "app", app->name);
    } else {
        len = snprintf(out, size, app->mf.setting_count ? "⚙️ `%s` settings:" : "`%s` has no settings.", app->name);
    }
    for (uint32_t i = 0; i < app->mf.setting_count; i++) {
        const cap_wasm_setting_t *s = &app->mf.settings[i];
        bool is_default = false;
        int32_t n = cap_wasm_cfg_get(app, s, value, sizeof(value), &is_default);

        if (json) {
            cJSON *item = cJSON_CreateObject();

            cJSON_AddStringToObject(item, "key", s->key);
            cJSON_AddStringToObject(item, "type", cap_wasm_setting_type_name(s->type));
            cJSON_AddStringToObject(item, "description", s->description);
            cJSON_AddBoolToObject(item, "secret", s->secret);
            cJSON_AddBoolToObject(item, "set", n >= 0);
            /* Secret values never reach the LLM, not even their length. */
            if (n >= 0 && !s->secret) {
                cJSON_AddStringToObject(item, "value", value);
                cJSON_AddBoolToObject(item, "default", is_default);
            }
            cJSON_AddItemToArray(list, item);
            continue;
        }
        len += snprintf(out + len, len < size ? size - len : 0, "\n`%s` (%s%s) = ", s->key,
                        cap_wasm_setting_type_name(s->type), s->secret ? ", secret" : "");
        if (n < 0) {
            len += snprintf(out + len, len < size ? size - len : 0, "unset");
        } else if (s->secret) {
            len += snprintf(out + len, len < size ? size - len : 0, "•••• (set, %d chars)", (int)n);
        } else {
            cap_wasm_cfg_display(value, shown, sizeof(shown));
            len += snprintf(out + len, len < size ? size - len : 0, "`%s`%s", shown, is_default ? " (default)" : "");
        }
        if (s->description[0]) {
            len += snprintf(out + len, len < size ? size - len : 0, " — %s", s->description);
        }
    }
    if (json) {
        rendered = root ? cJSON_PrintUnformatted(root) : NULL;
        snprintf(out, size, "%s", rendered ? rendered : "Error: out of memory");
        free(rendered);
        cJSON_Delete(root);
        return rendered ? ESP_OK : ESP_ERR_NO_MEM;
    }
    if (app->mf.setting_count) {
        snprintf(out + len, len < size ? size - len : 0, "\nSet: /app config %s <key> <value>\nReset: /app config %s "
                 "<key> --reset", app->name, app->name);
    }
    return ESP_OK;
}

esp_err_t cap_wasm_cfg_command(const cap_wasm_app_t *app, const char *args, bool json, char *out, size_t size)
{
    char key[CAP_WASM_SETTING_KEY_MAX + 2];
    char value[CAP_WASM_SETTING_VALUE_MAX + 1];
    char shown[CAP_WASM_SETTING_VALUE_MAX + 1];
    char ns[CAP_WASM_NVS_NS_LEN];
    const cap_wasm_setting_t *s;
    const char *rest;
    size_t key_len;
    bool reset;
    nvs_handle_t h;
    esp_err_t err;

    args = args ? args + strspn(args, " ") : "";
    if (json || !args[0]) {
        return cap_wasm_cfg_list(app, json, out, size);
    }
    key_len = strcspn(args, " ");
    rest = args + key_len;
    rest += strspn(rest, " ");
    s = cap_wasm_manifest_setting(&app->mf, args, key_len);
    if (!s) {
        snprintf(out, size, "`%s` has no setting '%.*s'; /app config %s lists them.", app->name,
                 (int)(key_len < sizeof(key) ? key_len : sizeof(key) - 1), args, app->name);
        return ESP_ERR_NOT_FOUND;
    }
    reset = strcmp(rest, CAP_WASM_CFG_RESET_ARG) == 0;
    if (!reset && !cap_wasm_setting_normalize(s, rest, value, sizeof(value))) {
        snprintf(out, size, "Invalid value for `%s` (%s): %s", s->key, cap_wasm_setting_type_name(s->type),
                 s->type == CAP_WASM_SETTING_INT ? "an integer is expected" :
                 s->type == CAP_WASM_SETTING_BOOL ? "use true/false, on/off, yes/no or 1/0" :
                 "1-256 bytes of text, no control characters");
        return ESP_ERR_INVALID_ARG;
    }
    cap_wasm_cfg_namespace(app->name, ns);
    err = nvs_open(ns, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = reset ? nvs_erase_key(h, s->key) : nvs_set_str(h, s->key, value);
        err = err == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : err;
        if (err == ESP_OK) {
            err = nvs_commit(h);
        }
        nvs_close(h);
    }
    if (err != ESP_OK) {
        snprintf(out, size, "Cannot store `%s`: %s", s->key, esp_err_to_name(err));
        return err;
    }
    /* Not logged: the value may be a secret. */
    ESP_LOGI(TAG, "[%s] setting %s %s", app->name, s->key, reset ? "reset" : "set");
    if (reset) {
        cap_wasm_cfg_display(s->def, shown, sizeof(shown));
        snprintf(out, size, s->has_default ? "Reset `%s` of `%s` to the default `%s`." : "Cleared `%s` of `%s`.",
                 s->key, app->name, shown);
    } else if (s->secret) {
        snprintf(out, size, "Set secret `%s` of `%s` (%u chars). You may want to delete your message with the value.",
                 s->key, app->name, (unsigned)strlen(value));
    } else {
        cap_wasm_cfg_display(value, shown, sizeof(shown));
        snprintf(out, size, "Set `%s` of `%s` to `%s`.", s->key, app->name, shown);
    }
    return ESP_OK;
}

void cap_wasm_cfg_prune(const cap_wasm_app_t *app)
{
    char keys[CAP_WASM_CFG_KEYS_MAX][NVS_KEY_NAME_MAX_SIZE];
    char value[CAP_WASM_SETTING_VALUE_MAX + 1];
    char norm[CAP_WASM_SETTING_VALUE_MAX + 1];
    char ns[CAP_WASM_NVS_NS_LEN];
    size_t count = 0;
    nvs_iterator_t it = NULL;
    nvs_handle_t h;
    esp_err_t err;

    cap_wasm_cfg_namespace(app->name, ns);
    err = nvs_entry_find(NVS_DEFAULT_PART_NAME, ns, NVS_TYPE_ANY, &it);
    while (err == ESP_OK && count < CAP_WASM_CFG_KEYS_MAX) {
        nvs_entry_info_t info;

        nvs_entry_info(it, &info);
        if (info.key[0] != '_') {
            strlcpy(keys[count++], info.key, sizeof(keys[0]));
        }
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    if (!count || nvs_open(ns, NVS_READWRITE, &h) != ESP_OK) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        const cap_wasm_setting_t *s = cap_wasm_manifest_setting(&app->mf, keys[i], strlen(keys[i]));
        size_t len = sizeof(value);

        /* Gone from the manifest, or no longer valid for its (changed) type. */
        if (!s || nvs_get_str(h, keys[i], value, &len) != ESP_OK ||
                !cap_wasm_setting_normalize(s, value, norm, sizeof(norm))) {
            ESP_LOGI(TAG, "[%s] dropping setting %s (no longer declared or invalid)", app->name, keys[i]);
            nvs_erase_key(h, keys[i]);
        }
    }
    nvs_commit(h);
    nvs_close(h);
}

uint32_t cap_wasm_timer_load(const char *app_name, uint32_t *last_unix)
{
    char ns[CAP_WASM_NVS_NS_LEN];
    uint32_t interval = 0;
    nvs_handle_t h;

    *last_unix = 0;
    cap_wasm_cfg_namespace(app_name, ns);
    if (nvs_open(ns, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, "_timer", &interval);
        nvs_get_u32(h, "_tlast", last_unix);
        nvs_close(h);
    }
    return interval;
}

void cap_wasm_timer_store(const char *app_name, uint32_t interval_s)
{
    char ns[CAP_WASM_NVS_NS_LEN];
    uint32_t old = 0;
    nvs_handle_t h;

    cap_wasm_cfg_namespace(app_name, ns);
    if (nvs_open(ns, NVS_READWRITE, &h) != ESP_OK) {
        ESP_LOGW(TAG, "[%s] cannot store the timer; it does not survive a reboot", app_name);
        return;
    }
    if (nvs_get_u32(h, "_timer", &old) != ESP_OK || old != interval_s) {
        if (interval_s) {
            nvs_set_u32(h, "_timer", interval_s);
        } else {
            nvs_erase_key(h, "_timer");
        }
        nvs_erase_key(h, "_tlast");
        nvs_commit(h);
    }
    nvs_close(h);
}

void cap_wasm_timer_store_last(const char *app_name, uint32_t last_unix)
{
    char ns[CAP_WASM_NVS_NS_LEN];
    nvs_handle_t h;

    cap_wasm_cfg_namespace(app_name, ns);
    if (nvs_open(ns, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u32(h, "_tlast", last_unix);
        nvs_commit(h);
        nvs_close(h);
    }
}

void cap_wasm_cfg_erase(const char *app_name)
{
    char ns[CAP_WASM_NVS_NS_LEN];
    nvs_handle_t h;

    cap_wasm_cfg_namespace(app_name, ns);
    if (nvs_open(ns, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
}

esp_err_t cap_wasm_apps_settings_json(const char *name, char *out, size_t size)
{
    return cap_wasm_admin(CAP_WASM_REQ_CONFIG_JSON, name, NULL, out, size);
}

esp_err_t cap_wasm_apps_set_setting(const char *name, const char *key, const char *value, char *out, size_t size)
{
    const char *arg = value ? value : CAP_WASM_CFG_RESET_ARG;
    size_t key_len = key ? strlen(key) : 0;
    size_t args_size;
    char *args;
    esp_err_t err;

    /* The request reuses the "/app config" arguments "<key> <value>|--reset". */
    if (!key_len || key_len > CAP_WASM_SETTING_KEY_MAX || strcspn(key, " ") != key_len) {
        snprintf(out, size, "Invalid setting key.");
        return ESP_ERR_INVALID_ARG;
    }
    if (value && strcmp(value, CAP_WASM_CFG_RESET_ARG) == 0) {
        snprintf(out, size, "Invalid value for `%s`: %s is reserved.", key, CAP_WASM_CFG_RESET_ARG);
        return ESP_ERR_INVALID_ARG;
    }
    args_size = key_len + 1 + strlen(arg) + 1;
    args = malloc(args_size);
    if (!args) {
        snprintf(out, size, "Error: out of memory");
        return ESP_ERR_NO_MEM;
    }
    snprintf(args, args_size, "%s %s", key, arg);
    err = cap_wasm_admin(CAP_WASM_REQ_CONFIG, name, args, out, size);
    free(args);
    return err;
}
