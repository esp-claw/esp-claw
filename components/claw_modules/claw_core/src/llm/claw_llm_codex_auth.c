/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "llm/claw_llm_codex_auth.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "llm/claw_llm_http_transport.h"
#include "nvs.h"

static const char *TAG = "codex_auth";

#define CODEX_CLIENT_ID "app_EMoamEEZ73f0CkXaXp7hrann"
#define CODEX_USERCODE_URL "https://auth.openai.com/api/accounts/deviceauth/usercode"
#define CODEX_DEVICE_TOKEN_URL "https://auth.openai.com/api/accounts/deviceauth/token"
#define CODEX_TOKEN_URL "https://auth.openai.com/oauth/token"
#define CODEX_REDIRECT_URI "https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback"
#define CODEX_HTTP_TIMEOUT_MS 15000
#define CODEX_REFRESH_SKEW_S 120
#define CODEX_DEVICE_TIMEOUT_S (15 * 60)
#define CODEX_USERCODE_MAX_ATTEMPTS 4
#define CODEX_NVS_NAMESPACE "codex_oauth"
#define CODEX_NVS_KEY "tokens"

typedef struct {
    char *access_token;
    char *refresh_token;
    char *account_id;
    int64_t expires_at;
} codex_tokens_t;

static SemaphoreHandle_t s_lock;

static char *dup_printf(const char *fmt, ...)
{
    va_list args;
    va_list copy;
    int needed;
    char *buf;

    va_start(args, fmt);
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(args);
        return NULL;
    }

    buf = calloc(1, (size_t)needed + 1);
    if (buf) {
        vsnprintf(buf, (size_t)needed + 1, fmt, args);
    }
    va_end(args);
    return buf;
}

static void tokens_free(codex_tokens_t *tokens)
{
    free(tokens->access_token);
    free(tokens->refresh_token);
    free(tokens->account_id);
    memset(tokens, 0, sizeof(*tokens));
}

static char *dup_json_string(const cJSON *root, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);

    return cJSON_IsString(item) && item->valuestring && item->valuestring[0] ?
           strdup(item->valuestring) : NULL;
}

/* Decodes unpadded base64url. Returns a heap buffer, sets out_len. */
static unsigned char *base64url_decode(const char *in, size_t in_len, size_t *out_len)
{
    unsigned char *out;
    uint32_t acc = 0;
    int bits = 0;
    size_t i;
    size_t o = 0;

    out = calloc(1, in_len * 3 / 4 + 4);
    if (!out) {
        return NULL;
    }
    for (i = 0; i < in_len; i++) {
        char c = in[i];
        uint32_t v;

        if (c >= 'A' && c <= 'Z') {
            v = (uint32_t)(c - 'A');
        } else if (c >= 'a' && c <= 'z') {
            v = (uint32_t)(c - 'a' + 26);
        } else if (c >= '0' && c <= '9') {
            v = (uint32_t)(c - '0' + 52);
        } else if (c == '-' || c == '+') {
            v = 62;
        } else if (c == '_' || c == '/') {
            v = 63;
        } else if (c == '=') {
            break;
        } else {
            free(out);
            return NULL;
        }
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    *out_len = o;
    return out;
}

/* Returns the JWT payload claims, or NULL if the token is not a parseable JWT. */
static cJSON *jwt_claims(const char *jwt)
{
    const char *payload = jwt ? strchr(jwt, '.') : NULL;
    const char *end = payload ? strchr(payload + 1, '.') : NULL;
    unsigned char *raw;
    char *json;
    size_t len = 0;
    cJSON *claims;

    if (!payload || !end || end == payload + 1) {
        return NULL;
    }
    payload++;
    raw = base64url_decode(payload, (size_t)(end - payload), &len);
    if (!raw) {
        return NULL;
    }
    json = calloc(1, len + 1);
    if (!json) {
        free(raw);
        return NULL;
    }
    memcpy(json, raw, len);
    claims = cJSON_Parse(json);
    free(json);
    free(raw);
    return claims;
}

static char *jwt_account_id(const cJSON *claims)
{
    const cJSON *auth = claims ? cJSON_GetObjectItemCaseSensitive(claims, "https://api.openai.com/auth") : NULL;

    return auth ? dup_json_string(auth, "chatgpt_account_id") : NULL;
}

static int64_t jwt_expiry(const cJSON *claims)
{
    const cJSON *exp = claims ? cJSON_GetObjectItemCaseSensitive(claims, "exp") : NULL;

    return cJSON_IsNumber(exp) ? (int64_t)exp->valuedouble : 0;
}

static esp_err_t tokens_save(const codex_tokens_t *tokens)
{
    nvs_handle_t handle;
    cJSON *root;
    char *json;
    esp_err_t err;

    root = cJSON_CreateObject();
    if (!root) {
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(root, "access_token", tokens->access_token);
    cJSON_AddStringToObject(root, "refresh_token", tokens->refresh_token);
    cJSON_AddStringToObject(root, "account_id", tokens->account_id);
    cJSON_AddNumberToObject(root, "expires_at", (double)tokens->expires_at);
    json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) {
        return ESP_ERR_NO_MEM;
    }

    err = nvs_open(CODEX_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        err = nvs_set_blob(handle, CODEX_NVS_KEY, json, strlen(json));
        if (err == ESP_OK) {
            err = nvs_commit(handle);
        }
        nvs_close(handle);
    }
    free(json);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to save Codex tokens: %s", esp_err_to_name(err));
    }
    return err;
}

static esp_err_t tokens_load(codex_tokens_t *tokens)
{
    nvs_handle_t handle;
    size_t len = 0;
    char *buf;
    cJSON *root;
    cJSON *expires;
    esp_err_t err;

    memset(tokens, 0, sizeof(*tokens));
    err = nvs_open(CODEX_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    }
    err = nvs_get_blob(handle, CODEX_NVS_KEY, NULL, &len);
    if (err != ESP_OK) {
        nvs_close(handle);
        return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    }
    buf = calloc(1, len + 1);
    if (!buf) {
        nvs_close(handle);
        return ESP_ERR_NO_MEM;
    }
    err = nvs_get_blob(handle, CODEX_NVS_KEY, buf, &len);
    nvs_close(handle);
    if (err == ESP_OK) {
        root = cJSON_Parse(buf);
        tokens->access_token = dup_json_string(root, "access_token");
        tokens->refresh_token = dup_json_string(root, "refresh_token");
        tokens->account_id = dup_json_string(root, "account_id");
        expires = cJSON_GetObjectItemCaseSensitive(root, "expires_at");
        tokens->expires_at = cJSON_IsNumber(expires) ? (int64_t)expires->valuedouble : 0;
        cJSON_Delete(root);
        if (!tokens->access_token || !tokens->refresh_token || !tokens->account_id) {
            err = ESP_ERR_INVALID_STATE;
        }
    }
    free(buf);
    if (err != ESP_OK) {
        tokens_free(tokens);
    }
    return err;
}

/* Parses an OAuth token response. Keeps fallback_refresh when the server omits a rotated token. */
static esp_err_t tokens_from_response(const char *body,
                                      const char *fallback_refresh,
                                      codex_tokens_t *tokens,
                                      char **out_error_message)
{
    cJSON *root = cJSON_Parse(body);
    cJSON *claims = NULL;

    memset(tokens, 0, sizeof(*tokens));
    if (!root) {
        *out_error_message = dup_printf("Token response is not JSON");
        return ESP_FAIL;
    }
    tokens->access_token = dup_json_string(root, "access_token");
    tokens->refresh_token = dup_json_string(root, "refresh_token");
    if (!tokens->refresh_token && fallback_refresh) {
        tokens->refresh_token = strdup(fallback_refresh);
    }
    claims = jwt_claims(tokens->access_token);
    tokens->account_id = jwt_account_id(claims);
    tokens->expires_at = jwt_expiry(claims);
    cJSON_Delete(claims);
    cJSON_Delete(root);

    if (!tokens->access_token || !tokens->refresh_token || !tokens->account_id) {
        tokens_free(tokens);
        *out_error_message = dup_printf("Token response is missing access_token, refresh_token or account id");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t post_request(const char *url,
                              const char *body,
                              const char *content_type,
                              claw_llm_http_response_t *out_response,
                              char **out_error_message)
{
    claw_llm_http_header_t headers[1] = {{.name = "Content-Type", .value = content_type}};
    claw_llm_http_json_request_t request = {0};

    request.url = url;
    request.body = body;
    request.auth_type = "none";
    request.timeout_ms = CODEX_HTTP_TIMEOUT_MS;
    request.headers = headers;
    request.header_count = 1;
    return claw_llm_http_post_json(&request, out_response, out_error_message);
}

static char *json_body(const char *key1, const char *value1, const char *key2, const char *value2)
{
    cJSON *root = cJSON_CreateObject();
    char *out = NULL;

    if (root) {
        cJSON_AddStringToObject(root, key1, value1);
        if (key2) {
            cJSON_AddStringToObject(root, key2, value2);
        }
        out = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }
    return out;
}

/* Exchanges a refresh token for new tokens and persists them before returning. */
static esp_err_t refresh_tokens(codex_tokens_t *tokens, char **out_error_message)
{
    claw_llm_http_response_t response = {0};
    codex_tokens_t fresh = {0};
    char *body;
    esp_err_t err;

    body = dup_printf("grant_type=refresh_token&refresh_token=%s&client_id=%s",
                      tokens->refresh_token, CODEX_CLIENT_ID);
    if (!body) {
        *out_error_message = dup_printf("Out of memory building refresh request");
        return ESP_ERR_NO_MEM;
    }
    err = post_request(CODEX_TOKEN_URL, body, "application/x-www-form-urlencoded", &response, out_error_message);
    free(body);
    if (err != ESP_OK) {
        if (response.status_code == 429) {
            ESP_LOGW(TAG, "Codex token refresh rate-limited; keeping stored tokens");
        }
        claw_llm_http_response_free(&response);
        return err;
    }

    err = tokens_from_response(response.body, tokens->refresh_token, &fresh, out_error_message);
    claw_llm_http_response_free(&response);
    if (err != ESP_OK) {
        return err;
    }
    err = tokens_save(&fresh);
    if (err != ESP_OK) {
        tokens_free(&fresh);
        *out_error_message = dup_printf("Failed to persist refreshed Codex tokens");
        return err;
    }
    tokens_free(tokens);
    *tokens = fresh;
    return ESP_OK;
}

esp_err_t claw_llm_codex_auth_init(void)
{
    if (!s_lock) {
        s_lock = xSemaphoreCreateMutex();
    }
    return s_lock ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t claw_llm_codex_device_start(claw_llm_codex_device_t *out_device, char **out_error_message)
{
    claw_llm_http_response_t response = {0};
    cJSON *root = NULL;
    cJSON *interval;
    char *body;
    int attempt;
    esp_err_t err = ESP_FAIL;

    memset(out_device, 0, sizeof(*out_device));
    body = json_body("client_id", CODEX_CLIENT_ID, NULL, NULL);
    if (!body) {
        *out_error_message = dup_printf("Out of memory building device code request");
        return ESP_ERR_NO_MEM;
    }

    for (attempt = 1; attempt <= CODEX_USERCODE_MAX_ATTEMPTS; attempt++) {
        int retry_after_s;
        int delay_s;

        err = post_request(CODEX_USERCODE_URL, body, "application/json", &response, out_error_message);
        if (err == ESP_OK || response.status_code != 429) {
            break;
        }
        retry_after_s = response.retry_after_s;
        claw_llm_http_response_free(&response);
        free(*out_error_message);
        *out_error_message = NULL;
        if (attempt == CODEX_USERCODE_MAX_ATTEMPTS) {
            *out_error_message = dup_printf("OpenAI is rate-limiting Codex login (HTTP 429). Try again later.");
            break;
        }
        delay_s = retry_after_s > 0 ? retry_after_s : (1 << attempt);
        if (delay_s > 60) {
            delay_s = 60;
        }
        ESP_LOGW(TAG, "Device code request rate-limited; retrying in %d s", delay_s);
        vTaskDelay(pdMS_TO_TICKS(delay_s * 1000));
    }
    free(body);
    if (err != ESP_OK) {
        if (*out_error_message == NULL) {
            *out_error_message = dup_printf("Device code request failed (HTTP %d)", response.status_code);
        }
        claw_llm_http_response_free(&response);
        return err;
    }

    root = cJSON_Parse(response.body);
    claw_llm_http_response_free(&response);
    out_device->user_code = dup_json_string(root, "user_code");
    out_device->device_auth_id = dup_json_string(root, "device_auth_id");
    interval = cJSON_GetObjectItemCaseSensitive(root, "interval");
    if (cJSON_IsString(interval) && interval->valuestring) {
        out_device->interval_s = atoi(interval->valuestring);
    } else if (cJSON_IsNumber(interval)) {
        out_device->interval_s = interval->valueint;
    }
    cJSON_Delete(root);

    if (!out_device->user_code || !out_device->device_auth_id) {
        claw_llm_codex_device_free(out_device);
        *out_error_message = dup_printf("Device code response is missing user_code or device_auth_id");
        return ESP_FAIL;
    }
    if (out_device->interval_s < 3) {
        out_device->interval_s = 3;
    }
    return ESP_OK;
}

/* Polls once. Returns ESP_OK with auth code and verifier when approved, ESP_ERR_NOT_FINISHED while pending. */
static esp_err_t device_poll_once(const claw_llm_codex_device_t *device,
                                  char **out_auth_code,
                                  char **out_verifier,
                                  char **out_error_message)
{
    claw_llm_http_response_t response = {0};
    cJSON *root;
    char *body;
    esp_err_t err;

    body = json_body("device_auth_id", device->device_auth_id, "user_code", device->user_code);
    if (!body) {
        *out_error_message = dup_printf("Out of memory building poll request");
        return ESP_ERR_NO_MEM;
    }
    err = post_request(CODEX_DEVICE_TOKEN_URL, body, "application/json", &response, out_error_message);
    free(body);
    if (err != ESP_OK) {
        if (response.status_code == 403 || response.status_code == 404) {
            free(*out_error_message);
            *out_error_message = NULL;
            claw_llm_http_response_free(&response);
            return ESP_ERR_NOT_FINISHED;
        }
        claw_llm_http_response_free(&response);
        return ESP_FAIL;
    }

    root = cJSON_Parse(response.body);
    claw_llm_http_response_free(&response);
    *out_auth_code = dup_json_string(root, "authorization_code");
    *out_verifier = dup_json_string(root, "code_verifier");
    cJSON_Delete(root);
    if (!*out_auth_code || !*out_verifier) {
        *out_error_message = dup_printf("Device auth response is missing authorization_code or code_verifier");
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t claw_llm_codex_device_wait(const claw_llm_codex_device_t *device, char **out_error_message)
{
    claw_llm_http_response_t response = {0};
    codex_tokens_t tokens = {0};
    char *auth_code = NULL;
    char *verifier = NULL;
    char *body;
    int waited_s = 0;
    esp_err_t err = ESP_ERR_TIMEOUT;

    if (!device || !device->user_code || !device->device_auth_id || !out_error_message) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_error_message = NULL;

    while (waited_s < CODEX_DEVICE_TIMEOUT_S) {
        vTaskDelay(pdMS_TO_TICKS(device->interval_s * 1000));
        waited_s += device->interval_s;
        err = device_poll_once(device, &auth_code, &verifier, out_error_message);
        if (err != ESP_ERR_NOT_FINISHED) {
            break;
        }
    }
    if (err == ESP_ERR_NOT_FINISHED) {
        err = ESP_ERR_TIMEOUT;
    }
    if (err == ESP_ERR_TIMEOUT) {
        *out_error_message = dup_printf("Login timed out after 15 minutes.");
        return err;
    }
    if (err != ESP_OK) {
        free(auth_code);
        free(verifier);
        return err;
    }

    body = dup_printf("grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s&code_verifier=%s",
                      auth_code, CODEX_REDIRECT_URI, CODEX_CLIENT_ID, verifier);
    free(auth_code);
    free(verifier);
    if (!body) {
        *out_error_message = dup_printf("Out of memory building token exchange");
        return ESP_ERR_NO_MEM;
    }
    err = post_request(CODEX_TOKEN_URL, body, "application/x-www-form-urlencoded", &response, out_error_message);
    free(body);
    if (err != ESP_OK) {
        claw_llm_http_response_free(&response);
        return err;
    }
    err = tokens_from_response(response.body, NULL, &tokens, out_error_message);
    claw_llm_http_response_free(&response);
    if (err != ESP_OK) {
        return err;
    }
    err = tokens_save(&tokens);
    tokens_free(&tokens);
    if (err != ESP_OK) {
        *out_error_message = dup_printf("Failed to save Codex login tokens");
    }
    return err;
}

void claw_llm_codex_device_free(claw_llm_codex_device_t *device)
{
    if (!device) {
        return;
    }
    free(device->user_code);
    free(device->device_auth_id);
    memset(device, 0, sizeof(*device));
}

esp_err_t claw_llm_codex_get_access_token(bool force_refresh,
                                          char **out_access_token,
                                          char **out_account_id,
                                          char **out_error_message)
{
    codex_tokens_t tokens = {0};
    esp_err_t err;
    time_t now = time(NULL);

    *out_access_token = NULL;
    *out_account_id = NULL;
    if (!s_lock) {
        *out_error_message = dup_printf("Codex auth is not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    err = tokens_load(&tokens);
    if (err == ESP_ERR_NOT_FOUND) {
        *out_error_message = dup_printf("Codex is not logged in. Run /llm codex login.");
    } else if (err != ESP_OK) {
        *out_error_message = dup_printf("Failed to load Codex tokens: %s", esp_err_to_name(err));
    } else if (force_refresh || (int64_t)now + CODEX_REFRESH_SKEW_S >= tokens.expires_at) {
        err = refresh_tokens(&tokens, out_error_message);
    }
    if (err == ESP_OK) {
        *out_access_token = strdup(tokens.access_token);
        *out_account_id = strdup(tokens.account_id);
        if (!*out_access_token || !*out_account_id) {
            err = ESP_ERR_NO_MEM;
            free(*out_access_token);
            free(*out_account_id);
            *out_access_token = NULL;
            *out_account_id = NULL;
        }
    }
    tokens_free(&tokens);
    xSemaphoreGive(s_lock);
    return err;
}

bool claw_llm_codex_is_logged_in(int64_t *out_expires_at)
{
    codex_tokens_t tokens = {0};
    bool logged_in = tokens_load(&tokens) == ESP_OK;

    if (out_expires_at) {
        *out_expires_at = logged_in ? tokens.expires_at : 0;
    }
    tokens_free(&tokens);
    return logged_in;
}

esp_err_t claw_llm_codex_logout(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(CODEX_NVS_NAMESPACE, NVS_READWRITE, &handle);

    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_erase_key(handle, CODEX_NVS_KEY);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        err = ESP_OK;
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err;
}
