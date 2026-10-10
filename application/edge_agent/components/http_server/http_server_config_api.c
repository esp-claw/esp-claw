/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "http_server_priv.h"

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/base64.h"

/*
 * Field catalogue
 *
 * Every NVS-backed config field is described here along with the group it
 * belongs to. The WebUI addresses fields by `name`; the C side stores them
 * in `app_config_t` at the given offset. Keeping the table in one place
 * lets both the GET (partial read) and POST (partial write) handlers share
 * the same serialisation logic.
 */

#define CONFIG_FIELD(group, field) { \
    #field, (group), \
    offsetof(app_config_t, field), \
    sizeof(((app_config_t *)0)->field) \
}

/* Secret fields are masked in GET; posting the mask back keeps the stored value. */
#define CONFIG_SECRET_FIELD(group, field) { \
    #field, (group), \
    offsetof(app_config_t, field), \
    sizeof(((app_config_t *)0)->field), \
    true \
}

#define CONFIG_SECRET_MASK "********"

typedef struct {
    const char *name;
    const char *group;
    size_t offset;
    size_t size;
    bool secret;
} config_field_def_t;

static const config_field_def_t CONFIG_FIELDS[] = {
    CONFIG_FIELD("wifi",         wifi_ssid),
    CONFIG_SECRET_FIELD("wifi",  wifi_password),
    CONFIG_FIELD("wifi",         ap_ssid),
    CONFIG_SECRET_FIELD("wifi",  ap_password),
    CONFIG_FIELD("wifi",         ap_behavior),

    CONFIG_SECRET_FIELD("llm",   llm_api_key),
    CONFIG_FIELD("llm",          llm_backend_type),
    CONFIG_FIELD("llm",          llm_model),
    CONFIG_FIELD("llm",          llm_base_url),
    CONFIG_FIELD("llm",          llm_auth_type),
    CONFIG_FIELD("llm",          llm_timeout_ms),
    CONFIG_FIELD("llm",          llm_max_tokens),
    CONFIG_FIELD("llm",          llm_default_image_max_bytes),
    CONFIG_FIELD("llm",          llm_max_tokens_field),
    CONFIG_FIELD("llm",          llm_supports_tools),
    CONFIG_FIELD("llm",          llm_supports_vision),
    CONFIG_FIELD("llm",          llm_image_remote_url_only),

    CONFIG_FIELD("im",           qq_app_id),
    CONFIG_SECRET_FIELD("im",    qq_app_secret),
    CONFIG_FIELD("im",           qq_msg_type),
    CONFIG_FIELD("im",           feishu_app_id),
    CONFIG_SECRET_FIELD("im",    feishu_app_secret),
    CONFIG_SECRET_FIELD("im",    tg_bot_token),
    CONFIG_FIELD("im",           tg_allowed_user_ids),
    CONFIG_SECRET_FIELD("im",    wechat_token),
    CONFIG_FIELD("im",           wechat_base_url),
    CONFIG_FIELD("im",           wechat_cdn_base_url),
    CONFIG_FIELD("im",           wechat_account_id),

    CONFIG_SECRET_FIELD("search", search_brave_key),
    CONFIG_SECRET_FIELD("search", search_tavily_key),
    CONFIG_FIELD("search",       search_http_allowlist),

    CONFIG_FIELD("stt",          stt_base_url),
    CONFIG_SECRET_FIELD("stt",   stt_api_key),
    CONFIG_FIELD("stt",          stt_model),

    CONFIG_FIELD("embed",        embed_base_url),
    CONFIG_SECRET_FIELD("embed", embed_api_key),
    CONFIG_FIELD("embed",        embed_model),

    CONFIG_FIELD("capabilities", enabled_cap_groups),
    CONFIG_FIELD("capabilities", llm_visible_cap_groups),
    CONFIG_FIELD("capabilities", ssh_hosts),
    CONFIG_FIELD("capabilities", wol_targets),
    CONFIG_SECRET_FIELD("capabilities", api_profiles),
    CONFIG_FIELD("capabilities", app_trusted_keys),
    CONFIG_FIELD("capabilities", app_allow_unsigned),

    CONFIG_FIELD("skills",       enabled_lua_modules),

    CONFIG_FIELD("time",         time_timezone),

    CONFIG_FIELD("webdav",       webdav_user),
    CONFIG_SECRET_FIELD("webdav", webdav_password),
};

static const size_t CONFIG_FIELD_COUNT = sizeof(CONFIG_FIELDS) / sizeof(CONFIG_FIELDS[0]);

static const char *TAG = "http_config_api";

/* ── Helpers ────────────────────────────────────────────────────────── */

static bool csv_contains(const char *csv, const char *token)
{
    if (!csv || !token) {
        return false;
    }
    size_t token_len = strlen(token);
    const char *cursor = csv;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == ',') {
            cursor++;
        }
        if (!*cursor) {
            break;
        }
        const char *comma = strchr(cursor, ',');
        size_t seg_len = comma ? (size_t)(comma - cursor) : strlen(cursor);
        while (seg_len > 0 && cursor[seg_len - 1] == ' ') {
            seg_len--;
        }
        if (seg_len == token_len && strncmp(cursor, token, token_len) == 0) {
            return true;
        }
        cursor += seg_len;
        if (comma) {
            cursor = comma + 1;
        }
    }
    return false;
}

static bool field_matches_filter(const config_field_def_t *field,
                                 const char *groups_csv,
                                 const char *fields_csv)
{
    if (!groups_csv && !fields_csv) {
        return true;
    }
    if (groups_csv && csv_contains(groups_csv, field->group)) {
        return true;
    }
    if (fields_csv && csv_contains(fields_csv, field->name)) {
        return true;
    }
    return false;
}

static const char *field_value(const app_config_t *config, const config_field_def_t *field)
{
    return ((const char *)config) + field->offset;
}

static char *field_mutable(app_config_t *config, const config_field_def_t *field)
{
    return ((char *)config) + field->offset;
}

static bool is_positive_decimal_string(const char *value)
{
    const unsigned char *cursor = (const unsigned char *)value;

    if (!cursor || !cursor[0]) {
        return false;
    }
    if (cursor[0] == '0') {
        return false;
    }

    while (*cursor) {
        if (!isdigit(*cursor)) {
            return false;
        }
        cursor++;
    }

    return true;
}

static bool is_boolean_string(const char *value)
{
    return value &&
           (strcmp(value, "true") == 0 ||
            strcmp(value, "false") == 0 ||
            strcmp(value, "1") == 0 ||
            strcmp(value, "0") == 0);
}

/* app_trusted_keys: "" or a JSON array of base64 raw 32-byte Ed25519 public keys. */
static bool is_trusted_keys_json(const char *value, size_t field_size)
{
    cJSON *keys = cJSON_Parse(value);
    const cJSON *key = NULL;
    bool valid = cJSON_IsArray(keys) && strlen(value) < field_size;

    cJSON_ArrayForEach(key, (valid ? keys : NULL)) {
        const char *b64 = cJSON_GetStringValue(key);
        unsigned char raw[33];
        size_t len = 0;

        valid = valid && b64 &&
                mbedtls_base64_decode(raw, sizeof(raw), &len, (const unsigned char *)b64, strlen(b64)) == 0 &&
                len == 32;
    }
    cJSON_Delete(keys);
    return valid;
}

static esp_err_t validate_wifi_config_fields(const app_config_t *config, const char **message)
{
    return app_config_validate_wifi(config, message);
}

static esp_err_t emit_config(httpd_req_t *req,
                             const app_config_t *config,
                             const char *groups_csv,
                             const char *fields_csv,
                             cJSON *extra_meta)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        /* emit_config owns extra_meta once called; free it here since it is
         * never attached to root on this failure path (caller does not). */
        cJSON_Delete(extra_meta);
        httpd_resp_send_500(req);
        return ESP_ERR_NO_MEM;
    }

    for (size_t i = 0; i < CONFIG_FIELD_COUNT; i++) {
        const config_field_def_t *field = &CONFIG_FIELDS[i];
        if (!field_matches_filter(field, groups_csv, fields_csv)) {
            continue;
        }
        const char *value = field_value(config, field);
        if (field->secret && value[0]) {
            value = CONFIG_SECRET_MASK;
        }
        http_server_json_add_string(root, field->name, value);
    }

    if (extra_meta) {
        cJSON_AddItemToObject(root, "_meta", extra_meta);
    }

    return http_server_send_json_response(req, root);
}

/* ── Handlers ───────────────────────────────────────────────────────── */

static esp_err_t config_get_handler(httpd_req_t *req)
{
    http_server_ctx_t *ctx = http_server_ctx();
    app_config_t *config = NULL;
    esp_err_t err;

    config = calloc(1, sizeof(*config));
    if (!config) {
        httpd_resp_send_500(req);
        return ESP_ERR_NO_MEM;
    }

    err = ctx->services.load_config(config);
    if (err != ESP_OK) {
        free(config);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to load config");
    }

    char filter_buf[192];
    char *groups_csv = NULL;
    char *fields_csv = NULL;
    bool include_meta = false;

    if (http_server_query_get(req, "groups", filter_buf, sizeof(filter_buf)) == ESP_OK) {
        groups_csv = strdup(filter_buf);
    }
    if (http_server_query_get(req, "fields", filter_buf, sizeof(filter_buf)) == ESP_OK) {
        fields_csv = strdup(filter_buf);
    }
    if (http_server_query_get(req, "meta", filter_buf, sizeof(filter_buf)) == ESP_OK) {
        include_meta = (filter_buf[0] == '1' || strcmp(filter_buf, "true") == 0);
    }

    cJSON *meta = NULL;
    if (include_meta) {
        meta = cJSON_CreateObject();
        cJSON *groups = meta ? cJSON_CreateArray() : NULL;
        cJSON *fields = meta ? cJSON_CreateArray() : NULL;
        if (meta && groups && fields) {
            for (size_t i = 0; i < CONFIG_FIELD_COUNT; i++) {
                const config_field_def_t *field = &CONFIG_FIELDS[i];
                cJSON *entry = cJSON_CreateObject();
                if (entry) {
                    cJSON_AddStringToObject(entry, "name", field->name);
                    cJSON_AddStringToObject(entry, "group", field->group);
                    cJSON_AddItemToArray(fields, entry);
                }
            }

            for (size_t i = 0; i < CONFIG_FIELD_COUNT; i++) {
                const char *name = CONFIG_FIELDS[i].group;
                bool seen = false;
                cJSON *existing = NULL;
                cJSON_ArrayForEach(existing, groups) {
                    if (cJSON_IsString(existing) && strcmp(existing->valuestring, name) == 0) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    cJSON_AddItemToArray(groups, cJSON_CreateString(name));
                }
            }

            cJSON_AddItemToObject(meta, "groups", groups);
            cJSON_AddItemToObject(meta, "fields", fields);
        } else {
            cJSON_Delete(groups);
            cJSON_Delete(fields);
            cJSON_Delete(meta);
            meta = NULL;
        }
    }

    esp_err_t send_err = emit_config(req, config, groups_csv, fields_csv, meta);
    free(config);
    free(groups_csv);
    free(fields_csv);
    return send_err;
}

static esp_err_t config_post_handler(httpd_req_t *req)
{
    http_server_ctx_t *ctx = http_server_ctx();
    app_config_t *config = NULL;
    esp_err_t err;

    config = calloc(1, sizeof(*config));
    if (!config) {
        httpd_resp_send_500(req);
        return ESP_ERR_NO_MEM;
    }

    err = ctx->services.load_config(config);
    if (err != ESP_OK) {
        free(config);
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to load config");
    }

    cJSON *root = NULL;
    err = http_server_parse_json_body(req, &root);
    if (err != ESP_OK) {
        free(config);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON body");
    }

    /* Partial writes: only fields present in the JSON body are applied.
     * Empty string is a valid value (lets the client clear a slot). */
    size_t applied_count = 0;

    for (size_t i = 0; i < CONFIG_FIELD_COUNT; i++) {
        const config_field_def_t *field = &CONFIG_FIELDS[i];
        cJSON *item = cJSON_GetObjectItemCaseSensitive(root, field->name);
        if (!cJSON_IsString(item)) {
            continue;
        }
        if (field->secret && strcmp(item->valuestring, CONFIG_SECRET_MASK) == 0) {
            /* Masked value echoed back by the WebUI: keep the stored secret. */
            applied_count++;
            continue;
        }
        if (strcmp(field->name, "llm_max_tokens") == 0 ||
                strcmp(field->name, "llm_default_image_max_bytes") == 0) {
            if (!is_positive_decimal_string(item->valuestring)) {
                cJSON_Delete(root);
                free(config);
                return httpd_resp_send_err(req,
                                           HTTPD_400_BAD_REQUEST,
                                           strcmp(field->name, "llm_max_tokens") == 0 ?
                                               "llm_max_tokens must be a positive integer" :
                                               "llm_default_image_max_bytes must be a positive integer");
            }
        }
        if ((strcmp(field->name, "llm_supports_tools") == 0 ||
                strcmp(field->name, "llm_supports_vision") == 0 ||
                strcmp(field->name, "llm_image_remote_url_only") == 0 ||
                strcmp(field->name, "app_allow_unsigned") == 0) &&
                !is_boolean_string(item->valuestring)) {
            cJSON_Delete(root);
            free(config);
            return httpd_resp_send_err(req,
                                       HTTPD_400_BAD_REQUEST,
                                       "Boolean fields must be true/false");
        }
        if (strcmp(field->name, "app_trusted_keys") == 0 && item->valuestring[0] &&
                !is_trusted_keys_json(item->valuestring, field->size)) {
            cJSON_Delete(root);
            free(config);
            return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                       "app_trusted_keys must be a JSON array of base64 32-byte Ed25519 "
                                       "public keys, at most 319 bytes");
        }
        if ((strcmp(field->name, "ssh_hosts") == 0 || strcmp(field->name, "wol_targets") == 0 ||
                strcmp(field->name, "api_profiles") == 0) &&
                item->valuestring[0]) {
            /* Truncated JSON would silently drop entries, so reject instead of clipping. */
            cJSON *hosts = cJSON_Parse(item->valuestring);
            bool valid = cJSON_IsArray(hosts) && strlen(item->valuestring) < field->size;

            cJSON_Delete(hosts);
            if (!valid) {
                cJSON_Delete(root);
                free(config);
                return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                           strcmp(field->name, "ssh_hosts") == 0 ?
                                               "ssh_hosts must be a JSON array of at most 1535 bytes" :
                                           strcmp(field->name, "api_profiles") == 0 ?
                                               "api_profiles must be a JSON array of at most 3583 bytes" :
                                               "wol_targets must be a JSON array of at most 1023 bytes");
            }
        }
        strlcpy(field_mutable(config, field), item->valuestring, field->size);
        applied_count++;
    }

    cJSON_Delete(root);

    if (applied_count == 0) {
        free(config);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                   "Request did not contain any recognised fields");
    }

    const char *wifi_config_error = NULL;
    err = validate_wifi_config_fields(config, &wifi_config_error);
    if (err != ESP_OK) {
        free(config);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, wifi_config_error);
    }

    err = ctx->services.save_config(config);
    if (err == ESP_OK) {
        http_server_webdav_apply_config(config);
    }
    free(config);
    if (err != ESP_OK) {
        /* Names the key and the error, never the value. */
        const char *failed_key = app_config_save_failed_key();
        char msg[96];

        snprintf(msg, sizeof(msg), "Failed to save config: %s%s%s", failed_key ? failed_key : "",
                 failed_key ? ": " : "", esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
    }

    ESP_LOGI(TAG, "Saved %u config field%s", (unsigned)applied_count, applied_count == 1 ? "" : "s");

    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"ok\":true}");
    }
    cJSON_AddBoolToObject(resp, "ok", true);
    cJSON_AddNumberToObject(resp, "applied", (double)applied_count);
    http_server_json_add_string(resp, "message",
                                "Saved. Restart the device to apply Wi-Fi, core LLM, capability, and Lua module changes.");
    return http_server_send_json_response(req, resp);
}

esp_err_t http_server_register_config_routes(httpd_handle_t server)
{
    const httpd_uri_t handlers[] = {
        { .uri = "/api/config", .method = HTTP_GET,  .handler = config_get_handler  },
        { .uri = "/api/config", .method = HTTP_POST, .handler = config_post_handler },
    };

    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); ++i) {
        esp_err_t err = http_server_register_uri(server, &handlers[i]);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}
