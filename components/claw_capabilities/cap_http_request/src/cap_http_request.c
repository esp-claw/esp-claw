/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_http_request.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "cJSON.h"
#include "claw_cap.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "sdkconfig.h"
#if CONFIG_APP_CLAW_CAP_IM_TG
#include "cap_im_tg.h"
#define CAP_HTTP_REQUEST_CAN_CONFIRM 1
#else
#define CAP_HTTP_REQUEST_CAN_CONFIRM 0
#endif

static const char *TAG = "cap_http_request";

#define CAP_HTTP_REQUEST_TIMEOUT_MS_DEFAULT 15000
#define CAP_HTTP_REQUEST_MAX_BODY_DEFAULT   (16 * 1024)
#define CAP_HTTP_REQUEST_MAX_BODY_LIMIT     ((64 * 1024) - 1)
#define CAP_HTTP_REQUEST_MAX_FILE_LIMIT     2147483647
#define CAP_HTTP_REQUEST_ALLOWLIST_MAX      320
#define CAP_HTTP_REQUEST_REDIRECT_URL_MAX   512
#define CAP_HTTP_REQUEST_PROFILE_NAME_MAX   32
#define CAP_HTTP_REQUEST_TOKEN_CACHE_MAX    4
#define CAP_HTTP_REQUEST_TOKEN_RESP_MAX     4096
#define CAP_HTTP_REQUEST_TOKEN_SLACK_S      60
/* 2020-01-01 UTC. Earlier wall-clock time means SNTP has not set the clock yet. */
#define CAP_HTTP_REQUEST_MIN_VALID_EPOCH    1577836800
#define CAP_HTTP_REQUEST_GOOGLE_TOKEN_URL   "https://oauth2.googleapis.com/token"
#define CAP_HTTP_REQUEST_PROMPT_MAX         2048
#define CAP_HTTP_REQUEST_PROMPT_URL_MAX     256
#define CAP_HTTP_REQUEST_PROMPT_BODY_MAX    300
#define CAP_HTTP_REQUEST_STATUS_RESERVE     96
#define CAP_HTTP_REQUEST_CONFIRM_TIMEOUT_MS 60000

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    size_t max_len;
    FILE *file;
    size_t file_bytes;
    size_t max_file_bytes;
    bool file_write_failed;
    bool truncated;
    bool check_redirect_allowlist;
    const cJSON *profile_hosts; /* when set, redirects must stay on https and these hosts */
    char redirect_location[CAP_HTTP_REQUEST_REDIRECT_URL_MAX];
} cap_http_request_buf_t;

typedef struct {
    char name[CAP_HTTP_REQUEST_PROFILE_NAME_MAX];
    char *token;
    time_t expires_at;
} cap_http_request_token_t;

typedef struct {
    char allowlist[CAP_HTTP_REQUEST_ALLOWLIST_MAX];
    char *profiles_json;
    SemaphoreHandle_t token_lock;
    cap_http_request_token_t tokens[CAP_HTTP_REQUEST_TOKEN_CACHE_MAX];
} cap_http_request_state_t;

static EXT_RAM_BSS_ATTR cap_http_request_state_t s_http_request = {0};

static bool cap_http_request_extract_url_host(const char *url, char *host, size_t host_size);
static bool cap_http_request_extract_redirect_host(const char *location,
                                                   esp_http_client_handle_t client,
                                                   char *host, size_t host_size);
static bool cap_http_request_host_allowed(const char *host);
static bool cap_http_request_host_in_list(const char *host, const cJSON *hosts);
static bool cap_http_request_profile_redirect_ok(const char *location, const char *host, const cJSON *hosts);

static esp_err_t cap_http_request_event_handler(esp_http_client_event_t *event)
{
    cap_http_request_buf_t *buf = NULL;
    size_t append_len;

    if (!event) {
        return ESP_OK;
    }

    buf = (cap_http_request_buf_t *)event->user_data;

    switch (event->event_id) {
    case HTTP_EVENT_ON_HEADER:
        if (buf && buf->check_redirect_allowlist &&
                event->header_key && event->header_value &&
                strcasecmp(event->header_key, "Location") == 0) {
            strlcpy(buf->redirect_location, event->header_value, sizeof(buf->redirect_location));
        }
        break;

    case HTTP_EVENT_REDIRECT:
        if (buf && buf->check_redirect_allowlist) {
            char host[128] = {0};

            if (!buf->redirect_location[0] ||
                    !cap_http_request_extract_redirect_host(buf->redirect_location, event->client,
                            host, sizeof(host)) ||
                    (buf->profile_hosts ?
                     !cap_http_request_profile_redirect_ok(buf->redirect_location, host, buf->profile_hosts) :
                     !cap_http_request_host_allowed(host))) {
                ESP_LOGW(TAG, "Redirect to '%s' blocked by allowlist", buf->redirect_location);
                return ESP_FAIL;
            }
            ESP_LOGI(TAG, "Redirect to host '%s' allowed by allowlist", host);
            buf->redirect_location[0] = '\0';
            return esp_http_client_set_redirection(event->client);
        }
        break;

    case HTTP_EVENT_ON_DATA:
        if (!buf || event->data_len <= 0) {
            break;
        }
        append_len = (size_t)event->data_len;

        if (buf->file) {
            size_t write_len = append_len;

            if (buf->max_file_bytes > 0) {
                if (buf->file_bytes >= buf->max_file_bytes) {
                    buf->truncated = true;
                    break;
                }
                if (write_len > buf->max_file_bytes - buf->file_bytes) {
                    write_len = buf->max_file_bytes - buf->file_bytes;
                    buf->truncated = true;
                }
            }
            if (write_len > 0 && fwrite(event->data, 1, write_len, buf->file) != write_len) {
                buf->file_write_failed = true;
                return ESP_FAIL;
            }
            buf->file_bytes += write_len;
            break;
        }

        if (!buf->data) {
            break;
        }
        if (buf->max_len > 0 && buf->len + append_len > buf->max_len) {
            if (buf->len >= buf->max_len) {
                buf->truncated = true;
                break;
            }
            append_len = buf->max_len - buf->len;
            buf->truncated = true;
        }
        if (buf->len + append_len + 1 > buf->cap) {
            size_t new_cap = buf->cap * 2;
            char *new_data = NULL;

            if (new_cap < buf->len + append_len + 1) {
                new_cap = buf->len + append_len + 1;
            }
            new_data = realloc(buf->data, new_cap);
            if (!new_data) {
                return ESP_ERR_NO_MEM;
            }
            buf->data = new_data;
            buf->cap = new_cap;
        }
        memcpy(buf->data + buf->len, event->data, append_len);
        buf->len += append_len;
        buf->data[buf->len] = '\0';
        break;

    default:
        break;
    }

    return ESP_OK;
}

static bool cap_http_request_is_valid_method(const char *method, esp_http_client_method_t *out_method)
{
    if (!method || !method[0]) {
        *out_method = HTTP_METHOD_GET;
        return true;
    }

    if (strcasecmp(method, "GET") == 0) {
        *out_method = HTTP_METHOD_GET;
        return true;
    }
    if (strcasecmp(method, "POST") == 0) {
        *out_method = HTTP_METHOD_POST;
        return true;
    }
    if (strcasecmp(method, "PUT") == 0) {
        *out_method = HTTP_METHOD_PUT;
        return true;
    }
    if (strcasecmp(method, "PATCH") == 0) {
        *out_method = HTTP_METHOD_PATCH;
        return true;
    }
    if (strcasecmp(method, "DELETE") == 0) {
        *out_method = HTTP_METHOD_DELETE;
        return true;
    }
    if (strcasecmp(method, "HEAD") == 0) {
        *out_method = HTTP_METHOD_HEAD;
        return true;
    }

    return false;
}

static bool cap_http_request_extract_url_host(const char *url, char *host, size_t host_size)
{
    const char *scheme = NULL;
    const char *authority = NULL;
    const char *authority_end = NULL;
    const char *start = NULL;
    const char *at = NULL;
    const char *host_end = NULL;
    size_t host_len = 0;

    if (!url || !host || host_size == 0) {
        return false;
    }
    host[0] = '\0';

    scheme = strstr(url, "://");
    if (!scheme || (strncasecmp(url, "http://", 7) != 0 && strncasecmp(url, "https://", 8) != 0)) {
        return false;
    }
    authority = scheme + 3;
    authority_end = authority + strcspn(authority, "/?#");
    if (authority >= authority_end) {
        return false;
    }

    start = authority;
    for (const char *p = authority; p < authority_end; p++) {
        if (*p == '@') {
            at = p;
        }
    }
    if (at) {
        start = at + 1;
    }

    if (start >= authority_end) {
        return false;
    }

    if (*start == '[') {
        const char *closing = NULL;
        for (const char *p = start + 1; p < authority_end; p++) {
            if (*p == ']') {
                closing = p;
                break;
            }
        }
        if (!closing || closing == start + 1) {
            return false;
        }
        host_len = (size_t)(closing - (start + 1));
        if (host_len + 1 > host_size) {
            return false;
        }
        memcpy(host, start + 1, host_len);
        host[host_len] = '\0';
        return true;
    }

    host_end = start;
    while (host_end < authority_end && *host_end != ':') {
        host_end++;
    }
    if (host_end <= start) {
        return false;
    }
    host_len = (size_t)(host_end - start);
    if (host_len + 1 > host_size) {
        return false;
    }
    memcpy(host, start, host_len);
    host[host_len] = '\0';
    return true;
}

static bool cap_http_request_extract_redirect_host(const char *location,
                                                   esp_http_client_handle_t client,
                                                   char *host, size_t host_size)
{
    char current_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX];
    char protocol_relative_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX + 8];

    if (!location || !location[0] || !host || host_size == 0) {
        return false;
    }

    if (cap_http_request_extract_url_host(location, host, host_size)) {
        return true;
    }

    if (location[0] == '/' && location[1] == '/') {
        if (snprintf(protocol_relative_url, sizeof(protocol_relative_url), "https:%s", location) >=
                (int)sizeof(protocol_relative_url)) {
            return false;
        }
        return cap_http_request_extract_url_host(protocol_relative_url, host, host_size);
    }

    if (!client) {
        return false;
    }

    if (esp_http_client_get_url(client, current_url, sizeof(current_url)) != ESP_OK) {
        return false;
    }

    return cap_http_request_extract_url_host(current_url, host, host_size);
}

static bool cap_http_request_host_matches_allowlist_token(const char *host, const char *token)
{
    size_t host_len;
    size_t token_len;

    if (!host || !token || !host[0] || !token[0]) {
        return false;
    }

    host_len = strlen(host);
    token_len = strlen(token);

    if (token_len == 1 && token[0] == '*') {
        return true;
    }

    if (token_len >= 3 && token[0] == '*' && token[1] == '.') {
        const char *base = token + 2;
        const char *suffix = token + 1;
        size_t suffix_len = token_len - 1;

        if (strcasecmp(host, base) == 0) {
            return true;
        }
        return host_len > suffix_len &&
               strcasecmp(host + host_len - suffix_len, suffix) == 0;
    }

    if (token[0] == '.') {
        const char *exact = token + 1;
        size_t token_with_dot_len = token_len;

        if (strcasecmp(host, exact) == 0) {
            return true;
        }
        return host_len > token_with_dot_len &&
               strcasecmp(host + host_len - token_with_dot_len, token) == 0;
    }

    return strcasecmp(host, token) == 0;
}

static bool cap_http_request_host_allowed(const char *host)
{
    char allowlist_copy[CAP_HTTP_REQUEST_ALLOWLIST_MAX];
    char *saveptr = NULL;
    char *token = NULL;

    if (!host || !host[0] || !s_http_request.allowlist[0]) {
        return false;
    }

    strlcpy(allowlist_copy, s_http_request.allowlist, sizeof(allowlist_copy));
    for (token = strtok_r(allowlist_copy, ",", &saveptr);
            token;
            token = strtok_r(NULL, ",", &saveptr)) {
        char *start = token;
        char *end = NULL;

        while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n') {
            start++;
        }
        end = start + strlen(start);
        while (end > start &&
                (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
            end--;
        }
        *end = '\0';
        if (!start[0]) {
            continue;
        }
        if (start[0] == '[' && end > start + 1 && end[-1] == ']') {
            start++;
            end[-1] = '\0';
        }
        if (cap_http_request_host_matches_allowlist_token(host, start)) {
            return true;
        }
    }

    return false;
}

static bool cap_http_request_host_in_list(const char *host, const cJSON *hosts)
{
    const cJSON *item = NULL;

    cJSON_ArrayForEach(item, hosts) {
        if (cJSON_IsString(item) && cap_http_request_host_matches_allowlist_token(host, item->valuestring)) {
            return true;
        }
    }
    return false;
}

/* Profile URLs must not contain whitespace, control bytes, backslashes, or userinfo, so this
 * parser and esp_http_client cannot disagree on the host the credentials are sent to. */
static bool cap_http_request_profile_url_ok(const char *url)
{
    const char *authority = strstr(url, "://");
    size_t authority_len;

    if (strncasecmp(url, "https://", 8) != 0 || !authority) {
        return false;
    }
    for (const char *p = url; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f || *p == '\\') {
            return false;
        }
    }
    authority += 3;
    authority_len = strcspn(authority, "/?#");
    return memchr(authority, '@', authority_len) == NULL;
}

/* Profile requests carry credentials: redirects must stay on https and on the profile hosts. */
static bool cap_http_request_profile_redirect_ok(const char *location, const char *host, const cJSON *hosts)
{
    if (strncasecmp(location, "https://", 8) == 0) {
        if (!cap_http_request_profile_url_ok(location)) {
            return false;
        }
    } else if (location[0] != '/' || location[1] == '/' || strpbrk(location, "\\\r\n")) {
        return false;
    }
    return cap_http_request_host_in_list(host, hosts);
}

static bool cap_http_request_header_value_ok(const char *value)
{
    return value && value[0] && !strpbrk(value, "\r\n");
}

/* Checks one api_profiles entry. Messages name fields only, never their values. */
static bool cap_http_request_profile_valid(const cJSON *profile, char *err, size_t err_size)
{
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(profile, "name"));
    const char *base_url = cJSON_GetStringValue(cJSON_GetObjectItem(profile, "base_url"));
    const cJSON *hosts = cJSON_GetObjectItem(profile, "hosts");
    const cJSON *auth = cJSON_GetObjectItem(profile, "auth");
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "type"));
    const cJSON *host = NULL;
    char base_host[128];

    if (!name || !name[0] || strlen(name) >= CAP_HTTP_REQUEST_PROFILE_NAME_MAX) {
        snprintf(err, err_size, "name must be a string of 1-%d bytes", CAP_HTTP_REQUEST_PROFILE_NAME_MAX - 1);
        return false;
    }
    if (!cJSON_IsArray(hosts) || cJSON_GetArraySize(hosts) == 0) {
        snprintf(err, err_size, "hosts must be a non-empty array");
        return false;
    }
    cJSON_ArrayForEach(host, hosts) {
        if (!cJSON_IsString(host) || !host->valuestring[0] || strcmp(host->valuestring, "*") == 0) {
            snprintf(err, err_size, "hosts entries must be host names or *.domain patterns");
            return false;
        }
    }
    if (!base_url || !cap_http_request_profile_url_ok(base_url) ||
            !cap_http_request_extract_url_host(base_url, base_host, sizeof(base_host)) ||
            !cap_http_request_host_in_list(base_host, hosts)) {
        snprintf(err, err_size, "base_url must be an https URL whose host matches hosts");
        return false;
    }
    if (type && strcmp(type, "bearer") == 0) {
        if (cap_http_request_header_value_ok(cJSON_GetStringValue(cJSON_GetObjectItem(auth, "token")))) {
            return true;
        }
        snprintf(err, err_size, "auth.token is missing or invalid");
        return false;
    }
    if (type && strcmp(type, "header") == 0) {
        const char *header = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "name"));

        if (header && header[0] && strspn(header, "abcdefghijklmnopqrstuvwxyz"
                                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == strlen(header) &&
                cap_http_request_header_value_ok(cJSON_GetStringValue(cJSON_GetObjectItem(auth, "value")))) {
            return true;
        }
        snprintf(err, err_size, "auth.name or auth.value is missing or invalid");
        return false;
    }
    if (type && strcmp(type, "google_service_account") == 0) {
        const cJSON *json = cJSON_GetObjectItem(auth, "json");
        const char *email = cJSON_GetStringValue(cJSON_GetObjectItem(json, "client_email"));
        const char *key = cJSON_GetStringValue(cJSON_GetObjectItem(json, "private_key"));
        const char *scopes = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "scopes"));

        if (email && email[0] && key && strstr(key, "-----BEGIN") && scopes && scopes[0]) {
            return true;
        }
        snprintf(err, err_size, "auth.json.client_email, auth.json.private_key and auth.scopes are required");
        return false;
    }
    snprintf(err, err_size, "auth.type must be bearer, header or google_service_account");
    return false;
}

static const cJSON *cap_http_request_find_profile(const cJSON *profiles, const char *name)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, profiles) {
        const char *entry_name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));

        if (entry_name && strcmp(entry_name, name) == 0) {
            return entry;
        }
    }
    return NULL;
}

static char *cap_http_request_b64url(const unsigned char *data, size_t len)
{
    size_t out_len = 0;
    size_t cap = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(cap);

    if (!out || mbedtls_base64_encode((unsigned char *)out, cap, &out_len, data, len) != 0) {
        free(out);
        return NULL;
    }
    while (out_len > 0 && out[out_len - 1] == '=') {
        out_len--;
    }
    out[out_len] = '\0';
    for (char *p = out; *p; p++) {
        *p = *p == '+' ? '-' : *p == '/' ? '_' : *p;
    }
    return out;
}

static int cap_http_request_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

/* Builds the RS256-signed JWT assertion for Google's OAuth 2.0 service account flow. */
static char *cap_http_request_google_jwt(const char *email, const char *pem, const char *scope, time_t now,
                                         char *err, size_t err_size)
{
    static const char header_b64[] = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"; /* {"alg":"RS256","typ":"JWT"} */
    cJSON *claims = cJSON_CreateObject();
    char *claims_json = NULL;
    char *claims_b64 = NULL;
    char *signing_input = NULL;
    char *sig_b64 = NULL;
    char *jwt = NULL;
    unsigned char hash[32];
    unsigned char *sig = malloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    size_t sig_len = 0;
    size_t len;
    mbedtls_pk_context pk;

    mbedtls_pk_init(&pk);
    if (claims) {
        cJSON_AddStringToObject(claims, "iss", email);
        cJSON_AddStringToObject(claims, "scope", scope);
        cJSON_AddStringToObject(claims, "aud", CAP_HTTP_REQUEST_GOOGLE_TOKEN_URL);
        cJSON_AddNumberToObject(claims, "iat", (double)now);
        cJSON_AddNumberToObject(claims, "exp", (double)now + 3600);
        claims_json = cJSON_PrintUnformatted(claims);
    }
    claims_b64 = claims_json ? cap_http_request_b64url((const unsigned char *)claims_json, strlen(claims_json)) : NULL;
    if (!sig || !claims_b64) {
        snprintf(err, err_size, "out of memory");
        goto cleanup;
    }
    len = sizeof(header_b64) + strlen(claims_b64) + 1;
    signing_input = malloc(len);
    if (!signing_input) {
        snprintf(err, err_size, "out of memory");
        goto cleanup;
    }
    snprintf(signing_input, len, "%s.%s", header_b64, claims_b64);
    if (mbedtls_pk_parse_key(&pk, (const unsigned char *)pem, strlen(pem) + 1, NULL, 0,
                             cap_http_request_rng, NULL) != 0 ||
            !mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        snprintf(err, err_size, "service account private_key is not a valid RSA PEM key");
        goto cleanup;
    }
    if (mbedtls_sha256((const unsigned char *)signing_input, strlen(signing_input), hash, 0) != 0 ||
            mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE,
                            &sig_len, cap_http_request_rng, NULL) != 0 ||
            !(sig_b64 = cap_http_request_b64url(sig, sig_len))) {
        snprintf(err, err_size, "failed to sign JWT");
        goto cleanup;
    }
    len = strlen(signing_input) + strlen(sig_b64) + 2;
    jwt = malloc(len);
    if (jwt) {
        snprintf(jwt, len, "%s.%s", signing_input, sig_b64);
    } else {
        snprintf(err, err_size, "out of memory");
    }

cleanup:
    mbedtls_pk_free(&pk);
    cJSON_Delete(claims);
    free(claims_json);
    free(claims_b64);
    free(signing_input);
    free(sig_b64);
    free(sig);
    return jwt;
}

/* Exchanges a fresh JWT for an access token; returns a malloc'd token and its lifetime. */
static char *cap_http_request_google_fetch(const char *jwt, int *expires_in, char *err, size_t err_size)
{
    static const char prefix[] = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=";
    cap_http_request_buf_t buf = {0};
    esp_http_client_config_t config = {
        .url = CAP_HTTP_REQUEST_GOOGLE_TOKEN_URL,
        .event_handler = cap_http_request_event_handler,
        .user_data = &buf,
        .timeout_ms = CAP_HTTP_REQUEST_TIMEOUT_MS_DEFAULT,
        .buffer_size = 4096,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .disable_auto_redirect = true,
        .method = HTTP_METHOD_POST,
    };
    esp_http_client_handle_t client = NULL;
    size_t form_len = sizeof(prefix) + strlen(jwt);
    char *form = malloc(form_len);
    char *token = NULL;
    cJSON *resp = NULL;
    esp_err_t http_err;
    int status;

    buf.cap = CAP_HTTP_REQUEST_TOKEN_RESP_MAX + 1;
    buf.max_len = CAP_HTTP_REQUEST_TOKEN_RESP_MAX;
    buf.data = calloc(1, buf.cap);
    client = form && buf.data ? esp_http_client_init(&config) : NULL;
    if (!client) {
        snprintf(err, err_size, "out of memory");
        goto cleanup;
    }
    snprintf(form, form_len, "%s%s", prefix, jwt);
    esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    esp_http_client_set_post_field(client, form, strlen(form));
    http_err = esp_http_client_perform(client);
    status = esp_http_client_get_status_code(client);
    if (http_err != ESP_OK) {
        snprintf(err, err_size, "token request failed (%s)", esp_err_to_name(http_err));
        goto cleanup;
    }
    resp = cJSON_Parse(buf.data);
    token = cJSON_GetStringValue(cJSON_GetObjectItem(resp, "access_token"));
    if (status != 200 || !token || !token[0] || !cap_http_request_header_value_ok(token)) {
        const char *error = cJSON_GetStringValue(cJSON_GetObjectItem(resp, "error"));
        const char *desc = cJSON_GetStringValue(cJSON_GetObjectItem(resp, "error_description"));

        snprintf(err, err_size, "token endpoint returned HTTP %d %s%s%s", status,
                 error ? error : "", desc ? ": " : "", desc ? desc : "");
        token = NULL;
        goto cleanup;
    }
    token = strdup(token);
    *expires_in = cJSON_IsNumber(cJSON_GetObjectItem(resp, "expires_in")) ?
                  cJSON_GetObjectItem(resp, "expires_in")->valueint : 3600;
    if (!token) {
        snprintf(err, err_size, "out of memory");
    }

cleanup:
    if (client) {
        esp_http_client_cleanup(client);
    }
    if (buf.data) {
        mbedtls_platform_zeroize(buf.data, buf.cap);
    }
    free(buf.data);
    free(form);
    cJSON_Delete(resp);
    return token;
}

/* Returns a malloc'd Google access token for the profile, cached until shortly before expiry. */
static char *cap_http_request_google_token(const char *profile_name, const cJSON *auth, char *err, size_t err_size)
{
    const cJSON *json = cJSON_GetObjectItem(auth, "json");
    cap_http_request_token_t *slot = NULL;
    char *token = NULL;
    char *jwt = NULL;
    int expires_in = 0;
    time_t now = time(NULL);

    if (now < CAP_HTTP_REQUEST_MIN_VALID_EPOCH) {
        snprintf(err, err_size, "system clock is not set yet (waiting for SNTP); cannot sign the Google JWT");
        return NULL;
    }

    xSemaphoreTake(s_http_request.token_lock, portMAX_DELAY);
    for (size_t i = 0; i < CAP_HTTP_REQUEST_TOKEN_CACHE_MAX; i++) {
        cap_http_request_token_t *entry = &s_http_request.tokens[i];

        if (strcmp(entry->name, profile_name) == 0) {
            slot = entry;
            break;
        }
        if (!slot && !entry->name[0]) {
            slot = entry;
        }
    }
    if (!slot) {
        slot = &s_http_request.tokens[0];
    }
    if (strcmp(slot->name, profile_name) == 0 && slot->token &&
            now < slot->expires_at - CAP_HTTP_REQUEST_TOKEN_SLACK_S) {
        token = strdup(slot->token);
        if (!token) {
            snprintf(err, err_size, "out of memory");
        }
        goto done;
    }

    jwt = cap_http_request_google_jwt(cJSON_GetStringValue(cJSON_GetObjectItem(json, "client_email")),
                                      cJSON_GetStringValue(cJSON_GetObjectItem(json, "private_key")),
                                      cJSON_GetStringValue(cJSON_GetObjectItem(auth, "scopes")),
                                      now, err, err_size);
    token = jwt ? cap_http_request_google_fetch(jwt, &expires_in, err, err_size) : NULL;
    if (token) {
        if (slot->token) {
            mbedtls_platform_zeroize(slot->token, strlen(slot->token));
            free(slot->token);
        }
        strlcpy(slot->name, profile_name, sizeof(slot->name));
        slot->token = strdup(token);
        slot->expires_at = now + expires_in;
    }

done:
    xSemaphoreGive(s_http_request.token_lock);
    free(jwt);
    return token;
}

/* Builds the profile's auth header; `*out_value` is malloc'd and holds a secret. */
static bool cap_http_request_profile_auth(const cJSON *profile, const char **out_name, char **out_value,
                                          char *err, size_t err_size)
{
    const cJSON *auth = cJSON_GetObjectItem(profile, "auth");
    const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "type"));
    const char *secret = NULL;
    char *google_token = NULL;
    size_t len;

    if (strcmp(type, "header") == 0) {
        *out_name = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "name"));
        *out_value = strdup(cJSON_GetStringValue(cJSON_GetObjectItem(auth, "value")));
        if (!*out_value) {
            snprintf(err, err_size, "out of memory");
        }
        return *out_value != NULL;
    }

    if (strcmp(type, "bearer") == 0) {
        secret = cJSON_GetStringValue(cJSON_GetObjectItem(auth, "token"));
    } else {
        google_token = cap_http_request_google_token(cJSON_GetStringValue(cJSON_GetObjectItem(profile, "name")),
                                                     auth, err, err_size);
        if (!google_token) {
            return false;
        }
        secret = google_token;
    }
    len = strlen("Bearer ") + strlen(secret) + 1;
    *out_name = "Authorization";
    *out_value = malloc(len);
    if (*out_value) {
        snprintf(*out_value, len, "Bearer %s", secret);
    } else {
        snprintf(err, err_size, "out of memory");
    }
    if (google_token) {
        mbedtls_platform_zeroize(google_token, strlen(google_token));
        free(google_token);
    }
    return *out_value != NULL;
}

#if CONFIG_APP_CLAW_CAP_IM_TG
/* Appends at most `max_text` bytes of `text` (cut on a UTF-8 boundary), HTML-escaped when
 * `escape` is set, keeping room for the status line added after the request. */
static void cap_http_request_html_put(char *html, size_t *len, const char *text, size_t max_text, bool escape)
{
    size_t text_len = strlen(text);
    bool cut = text_len > max_text;

    if (cut) {
        text_len = max_text;
        while (text_len > 0 && ((unsigned char)text[text_len] & 0xC0) == 0x80) {
            text_len--;
        }
    }
    for (size_t i = 0; i < text_len; i++) {
        const char *entity = !escape ? NULL :
                             text[i] == '&' ? "&amp;" :
                             text[i] == '<' ? "&lt;" :
                             text[i] == '>' ? "&gt;" : NULL;
        size_t n = entity ? strlen(entity) : 1;

        /* Leaves room for the 3-byte ellipsis. */
        if (*len + n + 4 >= CAP_HTTP_REQUEST_PROMPT_MAX - CAP_HTTP_REQUEST_STATUS_RESERVE) {
            cut = true;
            break;
        }
        memcpy(html + *len, entity ? entity : text + i, n);
        *len += n;
    }
    html[*len] = '\0';
    if (cut) {
        strlcat(html, "…", CAP_HTTP_REQUEST_PROMPT_MAX - CAP_HTTP_REQUEST_STATUS_RESERVE);
        *len = strlen(html);
    }
}

static void cap_http_request_finish_prompt(const char *chat_id, int64_t message_id, char *html, size_t prompt_len,
                                           const char *status)
{
    snprintf(html + prompt_len, CAP_HTTP_REQUEST_PROMPT_MAX - prompt_len, "\n\n<b>%s</b>", status);
    if (cap_im_tg_edit_message(chat_id, message_id, html) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to update confirmation message");
    }
}
#endif

/* Performs the request described by `input` (http_request's schema). With `out_status` the
 * output is the bare response body and the status is returned separately. */
static esp_err_t cap_http_request_run(const cJSON *input,
                                      const claw_cap_call_context_t *ctx,
                                      char *output,
                                      size_t output_size,
                                      int *out_status)
{
    cJSON *url_item = NULL;
    cJSON *method_item = NULL;
    cJSON *headers_item = NULL;
    cJSON *body_item = NULL;
    cJSON *timeout_item = NULL;
    cJSON *max_body_item = NULL;
    cJSON *save_path_item = NULL;
    cJSON *max_file_item = NULL;
    cJSON *profiles = NULL;
    const cJSON *profile = NULL;
    const char *profile_name = NULL;
    const char *path = NULL;
    const char *url = NULL;
    const char *auth_name = NULL;
    char *auth_value = NULL;
    char *profile_url = NULL;
#if CONFIG_APP_CLAW_CAP_IM_TG
    char *html = NULL;
    size_t prompt_len = 0;
    int64_t message_id = 0;
    bool prompt_settled = false;
#endif
    bool mutation = false;
    bool json_body = false;
    cap_http_request_buf_t buf = {0};
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    esp_http_client_method_t method = HTTP_METHOD_GET;
    esp_err_t err = ESP_OK;
    int status = 0;
    int timeout_ms = CAP_HTTP_REQUEST_TIMEOUT_MS_DEFAULT;
    int max_body_bytes = CAP_HTTP_REQUEST_MAX_BODY_DEFAULT;
    int max_file_bytes = 0;
    const char *save_path = NULL;
    char *save_path_copy = NULL;
    char *tmp_save_path = NULL;
    char host[128] = {0};
    char reason[160];

    url_item = cJSON_GetObjectItem(input, "url");
    method_item = cJSON_GetObjectItem(input, "method");
    headers_item = cJSON_GetObjectItem(input, "headers");
    body_item = cJSON_GetObjectItem(input, "body");
    timeout_item = cJSON_GetObjectItem(input, "timeout_ms");
    max_body_item = cJSON_GetObjectItem(input, "max_body_bytes");
    save_path_item = cJSON_GetObjectItem(input, "save_path");
    max_file_item = cJSON_GetObjectItem(input, "max_file_bytes");
    profile_name = cJSON_GetStringValue(cJSON_GetObjectItem(input, "profile"));
    path = cJSON_GetStringValue(cJSON_GetObjectItem(input, "path"));
    url = cJSON_GetStringValue(url_item);

    if (method_item && (!cJSON_IsString(method_item) ||
                        !cap_http_request_is_valid_method(method_item->valuestring, &method))) {
        snprintf(output, output_size, "Error: method must be GET/POST/PUT/PATCH/DELETE/HEAD");
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    if (profile_name) {
        /* Credentialed call: the profile's hosts replace the global allowlist. */
        profiles = s_http_request.profiles_json ? cJSON_Parse(s_http_request.profiles_json) : NULL;
        profile = cap_http_request_find_profile(profiles, profile_name);
        if (!profile) {
            snprintf(output, output_size, "Error: unknown API profile '%s' (see http_profiles)", profile_name);
            err = ESP_ERR_NOT_FOUND;
            goto cleanup;
        }
        if (!cap_http_request_profile_valid(profile, reason, sizeof(reason))) {
            snprintf(output, output_size, "Error: API profile '%s' is misconfigured: %s", profile_name, reason);
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        if ((path && path[0]) == (url && url[0])) {
            snprintf(output, output_size, "Error: with profile, pass exactly one of path or url");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (path && path[0]) {
            const char *base_url = cJSON_GetStringValue(cJSON_GetObjectItem(profile, "base_url"));
            size_t base_len = strlen(base_url);
            size_t len;

            if (path[0] != '/') {
                snprintf(output, output_size, "Error: path must start with /");
                err = ESP_ERR_INVALID_ARG;
                goto cleanup;
            }
            while (base_len > 0 && base_url[base_len - 1] == '/') {
                base_len--;
            }
            len = base_len + strlen(path) + 1;
            profile_url = malloc(len);
            if (!profile_url) {
                snprintf(output, output_size, "Error: out of memory");
                err = ESP_ERR_NO_MEM;
                goto cleanup;
            }
            snprintf(profile_url, len, "%.*s%s", (int)base_len, base_url, path);
            url = profile_url;
        }
        if (!cap_http_request_profile_url_ok(url) ||
                !cap_http_request_extract_url_host(url, host, sizeof(host))) {
            snprintf(output, output_size, "Error: profile requests need a plain https URL without userinfo or spaces");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (!cap_http_request_host_in_list(host, cJSON_GetObjectItem(profile, "hosts"))) {
            snprintf(output, output_size, "Error: host '%s' is not allowed for profile '%s'", host, profile_name);
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        buf.profile_hosts = cJSON_GetObjectItem(profile, "hosts");
        mutation = method != HTTP_METHOD_GET && method != HTTP_METHOD_HEAD;
        /* Mutations are confirmed in the Telegram chat the request came from. */
        if (mutation && (!ctx || ctx->caller != CLAW_CAP_CALLER_AGENT || !ctx->channel ||
                         strcmp(ctx->channel, "telegram") != 0 || !ctx->source_cap ||
                         strcmp(ctx->source_cap, "tg_gateway") != 0 || !ctx->chat_id || !ctx->chat_id[0] ||
                         !CAP_HTTP_REQUEST_CAN_CONFIRM)) {
            snprintf(output, output_size,
                     "Error: %s via a profile needs confirmation and is only available for requests "
                     "from an allowed Telegram chat; GET/HEAD work everywhere",
                     method_item->valuestring);
            err = ESP_ERR_NOT_SUPPORTED;
            goto cleanup;
        }
    } else {
        if (!s_http_request.allowlist[0]) {
            snprintf(output, output_size,
                     "Error: HTTP allowlist is empty; configure search_http_allowlist first");
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
        if (!url || !url[0]) {
            snprintf(output, output_size, "Error: missing url");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (strncasecmp(url, "http://", 7) != 0 && strncasecmp(url, "https://", 8) != 0) {
            snprintf(output, output_size, "Error: url must start with http:// or https://");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (!cap_http_request_extract_url_host(url, host, sizeof(host))) {
            snprintf(output, output_size, "Error: invalid url host");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (!cap_http_request_host_allowed(host)) {
            snprintf(output, output_size, "Error: host '%s' is not in allowlist", host);
            err = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
    }
    if (timeout_item) {
        if (!cJSON_IsNumber(timeout_item) ||
                timeout_item->valueint <= 0 ||
                timeout_item->valueint > 120000) {
            snprintf(output, output_size, "Error: timeout_ms must be an integer in [1, 120000]");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        timeout_ms = timeout_item->valueint;
    }
    if (max_body_item) {
        if (!cJSON_IsNumber(max_body_item) ||
                max_body_item->valueint <= 0 ||
                max_body_item->valueint > CAP_HTTP_REQUEST_MAX_BODY_LIMIT) {
            snprintf(output,
                     output_size,
                     "Error: max_body_bytes must be an integer in [1, %d]",
                     CAP_HTTP_REQUEST_MAX_BODY_LIMIT);
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        max_body_bytes = max_body_item->valueint;
    }
    if (save_path_item) {
        if (!cJSON_IsString(save_path_item) ||
                !save_path_item->valuestring ||
                !save_path_item->valuestring[0]) {
            snprintf(output, output_size, "Error: save_path must be a non-empty string");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        save_path = save_path_item->valuestring;
        save_path_copy = strdup(save_path);
        if (!save_path_copy) {
            snprintf(output, output_size, "Error: out of memory");
            err = ESP_ERR_NO_MEM;
            goto cleanup;
        }
    }
    if (max_file_item) {
        if (!save_path) {
            snprintf(output, output_size, "Error: max_file_bytes requires save_path");
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        if (!cJSON_IsNumber(max_file_item) ||
                max_file_item->valueint <= 0 ||
                max_file_item->valueint > CAP_HTTP_REQUEST_MAX_FILE_LIMIT) {
            snprintf(output,
                     output_size,
                     "Error: max_file_bytes must be an integer in [1, %d]",
                     CAP_HTTP_REQUEST_MAX_FILE_LIMIT);
            err = ESP_ERR_INVALID_ARG;
            goto cleanup;
        }
        max_file_bytes = max_file_item->valueint;
    }
    if (body_item && !cJSON_IsString(body_item)) {
        snprintf(output, output_size, "Error: body must be a string");
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }
    if (headers_item && !cJSON_IsObject(headers_item)) {
        snprintf(output, output_size, "Error: headers must be an object");
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }
    if (body_item &&
            (method == HTTP_METHOD_GET || method == HTTP_METHOD_HEAD) &&
            body_item->valuestring &&
            body_item->valuestring[0]) {
        snprintf(output, output_size, "Error: GET/HEAD does not accept body");
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }
    if (body_item && body_item->valuestring[0] &&
            !cJSON_GetObjectItem(headers_item, "Content-Type")) { /* case-insensitive lookup */
        cJSON *parsed_body = cJSON_Parse(body_item->valuestring);

        json_body = cJSON_IsObject(parsed_body) || cJSON_IsArray(parsed_body);
        cJSON_Delete(parsed_body);
    }

#if CONFIG_APP_CLAW_CAP_IM_TG
    if (mutation) {
        static const char *const labels[] = {"✅ Einmal", "❌ Abbrechen"};
        int choice = -1;

        html = heap_caps_malloc(CAP_HTTP_REQUEST_PROMPT_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!html) {
            snprintf(output, output_size, "Error: out of memory");
            err = ESP_ERR_NO_MEM;
            goto cleanup;
        }
        html[0] = '\0';
        cap_http_request_html_put(html, &prompt_len, "<b>API-Aufruf bestätigen</b>\nProfil: <b>", SIZE_MAX, false);
        cap_http_request_html_put(html, &prompt_len, profile_name, CAP_HTTP_REQUEST_PROFILE_NAME_MAX, true);
        cap_http_request_html_put(html, &prompt_len, "</b>\n<b>", SIZE_MAX, false);
        cap_http_request_html_put(html, &prompt_len, method_item->valuestring, 8, true);
        cap_http_request_html_put(html, &prompt_len, "</b> <code>", SIZE_MAX, false);
        cap_http_request_html_put(html, &prompt_len, url, CAP_HTTP_REQUEST_PROMPT_URL_MAX, true);
        cap_http_request_html_put(html, &prompt_len, "</code>", SIZE_MAX, false);
        if (body_item && body_item->valuestring[0]) {
            cap_http_request_html_put(html, &prompt_len, "\n<pre>", SIZE_MAX, false);
            cap_http_request_html_put(html, &prompt_len, body_item->valuestring,
                                      CAP_HTTP_REQUEST_PROMPT_BODY_MAX, true);
            cap_http_request_html_put(html, &prompt_len, "</pre>", SIZE_MAX, false);
        }
        err = cap_im_tg_confirm(ctx->chat_id, html, labels, 2, CAP_HTTP_REQUEST_CONFIRM_TIMEOUT_MS,
                                &choice, &message_id);
        if (err != ESP_OK) {
            snprintf(output, output_size, "Error: could not ask for confirmation in Telegram (%s)",
                     esp_err_to_name(err));
            goto cleanup;
        }
        if (choice != 0) {
            cap_http_request_finish_prompt(ctx->chat_id, message_id, html, prompt_len,
                                           choice < 0 ? "⌛ Zeitüberschreitung" : "❌ abgelehnt");
            snprintf(output, output_size, "Error: %s",
                     choice < 0 ? "Zeitüberschreitung: keine Bestätigung innerhalb von 60 s" : "abgelehnt vom Benutzer");
            err = choice < 0 ? ESP_ERR_TIMEOUT : ESP_FAIL;
            prompt_settled = true;
            goto cleanup;
        }
    }
#endif

    if (profile && !cap_http_request_profile_auth(profile, &auth_name, &auth_value, reason, sizeof(reason))) {
        snprintf(output, output_size, "Error: API profile '%s' auth failed: %s", profile_name, reason);
        err = ESP_FAIL;
        goto cleanup;
    }

    if (save_path_copy) {
        size_t tmp_path_len = strlen(save_path_copy) + sizeof(".tmp");

        tmp_save_path = malloc(tmp_path_len);
        if (!tmp_save_path) {
            snprintf(output, output_size, "Error: out of memory");
            err = ESP_ERR_NO_MEM;
            goto cleanup;
        }
        snprintf(tmp_save_path, tmp_path_len, "%s.tmp", save_path_copy);

        buf.file = fopen(tmp_save_path, "wb");
        if (!buf.file) {
            free(tmp_save_path);
            tmp_save_path = NULL;
            snprintf(output, output_size, "Error: failed to open save_path");
            err = ESP_FAIL;
            goto cleanup;
        }
        buf.max_file_bytes = (size_t)max_file_bytes;
    } else {
        buf.cap = ((size_t)max_body_bytes + 1 < 4096) ? (size_t)max_body_bytes + 1 : 4096;
        buf.data = calloc(1, buf.cap);
        if (!buf.data) {
            snprintf(output, output_size, "Error: out of memory");
            err = ESP_ERR_NO_MEM;
            goto cleanup;
        }
        buf.max_len = (size_t)max_body_bytes;
    }
    buf.check_redirect_allowlist = true;

    config.url = url;
    config.event_handler = cap_http_request_event_handler;
    config.user_data = &buf;
    config.timeout_ms = timeout_ms;
    config.buffer_size = 4096;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.disable_auto_redirect = true;

    client = esp_http_client_init(&config);
    if (!client) {
        snprintf(output, output_size, "Error: failed to init HTTP client");
        err = ESP_FAIL;
        goto cleanup;
    }

    esp_http_client_set_method(client, method);
    if (headers_item) {
        cJSON *header = NULL;

        cJSON_ArrayForEach(header, headers_item) {
            /* Profile credentials are injected below and must not be overridden by the model. */
            if (!header->string || (profile && (strcasecmp(header->string, "Authorization") == 0 ||
                                                strcasecmp(header->string, auth_name) == 0))) {
                continue;
            }
            if (cJSON_IsString(header) && header->valuestring) {
                esp_http_client_set_header(client, header->string, header->valuestring);
            }
        }
    }
    if (json_body) {
        esp_http_client_set_header(client, "Content-Type", "application/json");
    }
    if (auth_value) {
        esp_http_client_set_header(client, auth_name, auth_value);
    }
    if (body_item && body_item->valuestring) {
        esp_http_client_set_post_field(client, body_item->valuestring, strlen(body_item->valuestring));
    }

    err = esp_http_client_perform(client);
    status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (buf.file && fclose(buf.file) != 0 && err == ESP_OK) {
        buf.file_write_failed = true;
        err = ESP_FAIL;
    }
    buf.file = NULL;

    if (err != ESP_OK) {
        if (tmp_save_path) {
            remove(tmp_save_path);
        }
        snprintf(output,
                 output_size,
                 "Error: %s (%s)",
                 buf.file_write_failed ? "failed to write response file" : "http request failed",
                 esp_err_to_name(err));
        goto cleanup;
    }

    if (save_path_copy) {
        if (rename(tmp_save_path, save_path_copy) != 0) {
            remove(save_path_copy);
            if (rename(tmp_save_path, save_path_copy) != 0) {
                remove(tmp_save_path);
                snprintf(output, output_size, "Error: failed to finalize save_path");
                err = ESP_FAIL;
                goto cleanup;
            }
        }
        snprintf(output,
                 output_size,
                 "HTTP %d%s\nSaved response body to %s (%zu bytes)",
                 status,
                 buf.truncated ? " (file truncated)" : "",
                 save_path_copy,
                 buf.file_bytes);
    } else if (out_status) {
        *out_status = status;
        snprintf(output, output_size, "%s", buf.data ? buf.data : "");
    } else {
        snprintf(output,
                 output_size,
                 "HTTP %d%s\n%s",
                 status,
                 buf.truncated ? " (body truncated)" : "",
                 buf.data ? buf.data : "");
    }

cleanup:
#if CONFIG_APP_CLAW_CAP_IM_TG
    if (message_id && !prompt_settled) {
        char done[32];

        if (err != ESP_OK) {
            strlcpy(done, "⚠️ fehlgeschlagen", sizeof(done));
        } else {
            snprintf(done, sizeof(done), "%s HTTP %d", status >= 200 && status < 400 ? "✅" : "⚠️", status);
        }
        cap_http_request_finish_prompt(ctx->chat_id, message_id, html, prompt_len, done);
    }
    free(html);
#endif
    if (buf.file) {
        fclose(buf.file);
        remove(tmp_save_path);
    }
    if (auth_value) {
        mbedtls_platform_zeroize(auth_value, strlen(auth_value));
    }
    free(auth_value);
    free(profile_url);
    free(buf.data);
    free(tmp_save_path);
    free(save_path_copy);
    cJSON_Delete(profiles);
    return err;
}

static esp_err_t cap_http_request_execute(const char *input_json,
                                          const claw_cap_call_context_t *ctx,
                                          char *output,
                                          size_t output_size)
{
    cJSON *input = NULL;
    esp_err_t err;

    if (!output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    input = cJSON_Parse(input_json);
    if (!input) {
        snprintf(output, output_size, "Error: invalid input JSON");
        return ESP_ERR_INVALID_ARG;
    }
    err = cap_http_request_run(input, ctx, output, output_size, NULL);
    cJSON_Delete(input);
    return err;
}

esp_err_t cap_http_request_profile_call(const char *profile, const char *method, const char *path_or_url,
                                        const char *headers_json, const char *body, size_t max_body,
                                        const claw_cap_call_context_t *ctx,
                                        int *out_status, char *output, size_t output_size)
{
    cJSON *input = cJSON_CreateObject();
    cJSON *headers = headers_json && headers_json[0] ? cJSON_Parse(headers_json) : NULL;
    esp_err_t err;

    if (!profile || !profile[0] || !path_or_url || !out_status || !output || output_size == 0) {
        cJSON_Delete(input);
        cJSON_Delete(headers);
        return ESP_ERR_INVALID_ARG;
    }
    if (!input || (headers_json && headers_json[0] && !cJSON_IsObject(headers))) {
        snprintf(output, output_size, "Error: %s", input ? "headers must be a JSON object" : "out of memory");
        cJSON_Delete(input);
        cJSON_Delete(headers);
        return input ? ESP_ERR_INVALID_ARG : ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(input, "profile", profile);
    cJSON_AddStringToObject(input, "method", method && method[0] ? method : "GET");
    cJSON_AddStringToObject(input, path_or_url[0] == '/' ? "path" : "url", path_or_url);
    if (headers) {
        cJSON_AddItemToObject(input, "headers", headers);
    }
    if (body && body[0]) {
        cJSON_AddStringToObject(input, "body", body);
    }
    cJSON_AddNumberToObject(input, "max_body_bytes", (double)max_body);
    err = cap_http_request_run(input, ctx, output, output_size, out_status);
    cJSON_Delete(input);
    return err;
}

/* Lists profiles without their auth section, so the model can pick one without seeing secrets. */
static esp_err_t cap_http_request_profiles_execute(const char *input_json,
                                                   const claw_cap_call_context_t *ctx,
                                                   char *output,
                                                   size_t output_size)
{
    cJSON *profiles = s_http_request.profiles_json ? cJSON_Parse(s_http_request.profiles_json) : NULL;
    cJSON *list = cJSON_CreateArray();
    const cJSON *entry = NULL;
    char *rendered = NULL;
    char reason[160];

    (void)input_json;
    (void)ctx;

    cJSON_ArrayForEach(entry, profiles) {
        cJSON *item = cJSON_CreateObject();

        if (!item) {
            break;
        }
        cJSON_AddItemToObject(item, "name", cJSON_Duplicate(cJSON_GetObjectItem(entry, "name"), false));
        cJSON_AddItemToObject(item, "base_url", cJSON_Duplicate(cJSON_GetObjectItem(entry, "base_url"), false));
        cJSON_AddItemToObject(item, "hosts", cJSON_Duplicate(cJSON_GetObjectItem(entry, "hosts"), true));
        if (!cap_http_request_profile_valid(entry, reason, sizeof(reason))) {
            cJSON_AddStringToObject(item, "error", reason);
        }
        cJSON_AddItemToArray(list, item);
    }
    rendered = list ? cJSON_PrintUnformatted(list) : NULL;
    snprintf(output, output_size, "%s", rendered ? rendered : "Error: out of memory");
    free(rendered);
    cJSON_Delete(list);
    cJSON_Delete(profiles);
    return rendered ? ESP_OK : ESP_ERR_NO_MEM;
}

static const claw_cap_descriptor_t s_http_request_descriptors[] = {
    {
        .id = "http_request",
        .name = "http_request",
        .family = "system",
        .description = "Call a standard HTTP endpoint with allowlist protection, or an API through a "
        "configured credential profile (auth is injected by the device; never pass tokens).",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"url\":{\"type\":\"string\"},"
        "\"profile\":{\"type\":\"string\",\"description\":\"API profile name from http_profiles\"},"
        "\"path\":{\"type\":\"string\",\"description\":\"With profile: path appended to its base_url\"},"
        "\"method\":{\"type\":\"string\",\"enum\":[\"GET\",\"POST\",\"PUT\",\"PATCH\",\"DELETE\",\"HEAD\"]},"
        "\"headers\":{\"type\":\"object\",\"additionalProperties\":{\"type\":\"string\"}},"
        "\"body\":{\"type\":\"string\"},"
        "\"save_path\":{\"type\":\"string\"},"
        "\"timeout_ms\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":120000},"
        "\"max_body_bytes\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":65535},"
        "\"max_file_bytes\":{\"type\":\"integer\",\"minimum\":1,\"maximum\":2147483647}}}",
        .execute = cap_http_request_execute,
    },
    {
        .id = "http_profiles",
        .name = "http_profiles",
        .family = "system",
        .description = "List configured HTTP API credential profiles (name, base_url, hosts); secrets are never shown.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_http_request_profiles_execute,
    },
};

static const claw_cap_group_t s_http_request_group = {
    .group_id = "cap_http_request",
    .descriptors = s_http_request_descriptors,
    .descriptor_count = sizeof(s_http_request_descriptors) / sizeof(s_http_request_descriptors[0]),
};

esp_err_t cap_http_request_register_group(void)
{
    if (claw_cap_group_exists(s_http_request_group.group_id)) {
        return ESP_OK;
    }
    if (!s_http_request.token_lock) {
        s_http_request.token_lock = xSemaphoreCreateMutex();
        if (!s_http_request.token_lock) {
            return ESP_ERR_NO_MEM;
        }
    }

    return claw_cap_register_group(&s_http_request_group);
}

esp_err_t cap_http_request_set_allowlist(const char *allowlist_csv)
{
    if (!allowlist_csv) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_http_request.allowlist, allowlist_csv, sizeof(s_http_request.allowlist));
    return ESP_OK;
}

esp_err_t cap_http_request_set_profiles(const char *profiles_json)
{
    cJSON *profiles = NULL;
    const cJSON *entry = NULL;
    char *copy = NULL;
    char reason[160];
    int index = 0;

    if (!profiles_json) {
        return ESP_ERR_INVALID_ARG;
    }
    if (profiles_json[0]) {
        copy = strdup(profiles_json);
        if (!copy) {
            return ESP_ERR_NO_MEM;
        }
        profiles = cJSON_Parse(profiles_json);
        if (!cJSON_IsArray(profiles)) {
            ESP_LOGW(TAG, "api_profiles is not a JSON array; profiles are unavailable");
        }
        cJSON_ArrayForEach(entry, (cJSON_IsArray(profiles) ? profiles : NULL)) {
            if (!cap_http_request_profile_valid(entry, reason, sizeof(reason))) {
                ESP_LOGW(TAG, "api_profiles[%d]: %s", index, reason);
            }
            index++;
        }
        cJSON_Delete(profiles);
    }
    if (s_http_request.profiles_json) {
        mbedtls_platform_zeroize(s_http_request.profiles_json, strlen(s_http_request.profiles_json));
        free(s_http_request.profiles_json);
    }
    s_http_request.profiles_json = copy;
    ESP_LOGI(TAG, "Loaded %d API profile%s", index, index == 1 ? "" : "s");
    return ESP_OK;
}
