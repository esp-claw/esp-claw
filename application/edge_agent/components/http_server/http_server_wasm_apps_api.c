/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * WASM app management for the web UI. The UI is an authenticated user channel, so it may change
 * app settings directly (the agent and Lua cannot); secret setting values are never returned.
 */
#include "http_server_priv.h"

#include <stdlib.h>
#include <string.h>

#include "cap_wasm_apps.h"

#define WASM_APPS_OUT_SIZE  (16 * 1024) /* status JSON of every app, or a settings listing */
#define WASM_APPS_NAME_SIZE 32
#define WASM_APPS_KEY_SIZE  32

static const char *wasm_apps_http_status(esp_err_t err)
{
    switch (err) {
    case ESP_ERR_NOT_FOUND:
        return "404 Not Found";
    case ESP_ERR_INVALID_ARG:
    case ESP_ERR_NOT_SUPPORTED:
        return "400 Bad Request";
    case ESP_ERR_INVALID_STATE:
    case ESP_ERR_TIMEOUT:
        return "503 Service Unavailable";
    default:
        return "500 Internal Server Error";
    }
}

/* Sends `out` as JSON on success (`json`) or {"ok":true,"message":out}; as plain-text error otherwise. */
static esp_err_t wasm_apps_send(httpd_req_t *req, esp_err_t err, const char *out, bool json)
{
    cJSON *root;

    if (err != ESP_OK) {
        httpd_resp_set_status(req, wasm_apps_http_status(err));
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        return httpd_resp_sendstr(req, out[0] ? out : esp_err_to_name(err));
    }
    if (json) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
        return httpd_resp_sendstr(req, out);
    }
    root = cJSON_CreateObject();
    if (!root) {
        httpd_resp_send_500(req);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddBoolToObject(root, "ok", true);
    http_server_json_add_string(root, "message", out);
    return http_server_send_json_response(req, root);
}

static char *wasm_apps_alloc_out(httpd_req_t *req)
{
    char *out = calloc(1, WASM_APPS_OUT_SIZE);

    if (!out) {
        httpd_resp_send_500(req);
    }
    return out;
}

static esp_err_t wasm_apps_list_handler(httpd_req_t *req)
{
    char *out = wasm_apps_alloc_out(req);
    esp_err_t ret;

    if (!out) {
        return ESP_ERR_NO_MEM;
    }
    ret = wasm_apps_send(req, cap_wasm_apps_status_json(out, WASM_APPS_OUT_SIZE), out, true);
    free(out);
    return ret;
}

static esp_err_t wasm_apps_settings_handler(httpd_req_t *req)
{
    char name[WASM_APPS_NAME_SIZE] = "";
    char *out;
    esp_err_t ret;

    if (http_server_query_get(req, "name", name, sizeof(name)) != ESP_OK || !name[0]) {
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "name is required");
    }
    out = wasm_apps_alloc_out(req);
    if (!out) {
        return ESP_ERR_NO_MEM;
    }
    ret = wasm_apps_send(req, cap_wasm_apps_settings_json(name, out, WASM_APPS_OUT_SIZE), out, true);
    free(out);
    return ret;
}

/* Parses the body and its required "name"; sends the error response itself on failure. */
static cJSON *wasm_apps_parse_body(httpd_req_t *req, char name[WASM_APPS_NAME_SIZE])
{
    cJSON *root = NULL;

    if (http_server_parse_json_body(req, &root) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON body");
        return NULL;
    }
    name[0] = '\0';
    http_server_json_read_string(root, "name", name, WASM_APPS_NAME_SIZE);
    if (!name[0]) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "name is required");
        return NULL;
    }
    return root;
}

static esp_err_t wasm_apps_enabled_handler(httpd_req_t *req)
{
    char name[WASM_APPS_NAME_SIZE];
    cJSON *root = wasm_apps_parse_body(req, name);
    cJSON *enabled;
    char *out;
    esp_err_t ret;

    if (!root) {
        return ESP_FAIL;
    }
    enabled = cJSON_GetObjectItemCaseSensitive(root, "enabled");
    if (!cJSON_IsBool(enabled)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "enabled (boolean) is required");
    }
    out = wasm_apps_alloc_out(req);
    if (!out) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    ret = wasm_apps_send(req, cap_wasm_apps_set_enabled(name, cJSON_IsTrue(enabled), out, WASM_APPS_OUT_SIZE),
                         out, false);
    cJSON_Delete(root);
    free(out);
    return ret;
}

static esp_err_t wasm_apps_setting_handler(httpd_req_t *req)
{
    char name[WASM_APPS_NAME_SIZE];
    char key[WASM_APPS_KEY_SIZE] = "";
    cJSON *root = wasm_apps_parse_body(req, name);
    const char *value;
    bool reset;
    char *out;
    esp_err_t ret;

    if (!root) {
        return ESP_FAIL;
    }
    http_server_json_read_string(root, "key", key, sizeof(key));
    value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(root, "value"));
    reset = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(root, "reset"));
    if (!key[0] || reset == (value != NULL)) {
        cJSON_Delete(root);
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "key and either value (string) or reset:true are required");
    }
    out = wasm_apps_alloc_out(req);
    if (!out) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }
    ret = wasm_apps_send(req, cap_wasm_apps_set_setting(name, key, reset ? NULL : value, out, WASM_APPS_OUT_SIZE),
                         out, false);
    cJSON_Delete(root);
    free(out);
    return ret;
}

esp_err_t http_server_register_wasm_apps_routes(httpd_handle_t server)
{
    const httpd_uri_t handlers[] = {
        { .uri = "/api/wasm-apps", .method = HTTP_GET, .handler = wasm_apps_list_handler },
        { .uri = "/api/wasm-apps/settings", .method = HTTP_GET, .handler = wasm_apps_settings_handler },
        { .uri = "/api/wasm-apps/enabled", .method = HTTP_POST, .handler = wasm_apps_enabled_handler },
        { .uri = "/api/wasm-apps/setting", .method = HTTP_POST, .handler = wasm_apps_setting_handler },
    };

    for (size_t i = 0; i < sizeof(handlers) / sizeof(handlers[0]); i++) {
        esp_err_t err = http_server_register_uri(server, &handlers[i]);
        if (err != ESP_OK) {
            return err;
        }
    }
    return ESP_OK;
}
