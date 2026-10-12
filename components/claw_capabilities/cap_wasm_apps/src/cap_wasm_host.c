/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Host API v2 (import module "claw"; CAP_WASM_API_VERSION). Every app buffer is declared as "*~" (pointer + length) in
 * the native signature, so WAMR bounds-checks it against the app's linear memory before the
 * native runs and traps the call otherwise. Natives run on the WASM thread only.
 */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "cap_http_request.h"
#include "cap_wasm_internal.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "nvs.h"
#include "ping/ping_sock.h"
#include "sdkconfig.h"

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_LOG_MAX            512
#define CAP_WASM_LOGS_PER_CALL      32
#define CAP_WASM_RESULT_MAX         (16 * 1024)
#define CAP_WASM_RESPONSE_MAX       (32 * 1024)
#define CAP_WASM_KV_KEY_MAX         15   /* NVS key limit */
#define CAP_WASM_KV_VALUE_MAX       1024
#define CAP_WASM_KV_MAX_KEYS        32
#define CAP_WASM_KV_WRITES_PER_CALL 16
#define CAP_WASM_ARG_MAX            1024 /* profile, method, URL/path */
#define CAP_WASM_HEADERS_MAX        2048
#define CAP_WASM_BODY_MAX           (16 * 1024)
#define CAP_WASM_CONFIRM_TEXT_MAX   1024
#define CAP_WASM_CONFIRM_TIMEOUT_MS 60000
#define CAP_WASM_PING_MAX_COUNT     10
#define CAP_WASM_PING_TIMEOUT_MS    1000
#define CAP_WASM_PING_INTERVAL_MS   200
#define CAP_WASM_HOST_NAME_MAX      253
#define CAP_WASM_NOTIFY_MAX         1000
#define CAP_WASM_NOTIFY_PER_HOUR    10

cap_wasm_call_t g_cap_wasm_call;

static cap_wasm_app_t *cap_wasm_env_app(wasm_exec_env_t env)
{
    return wasm_runtime_get_custom_data(wasm_runtime_get_module_inst(env));
}

/* Copies an app string into a NUL-terminated heap buffer; NULL when longer than max_len. */
static char *cap_wasm_strndup(const char *src, uint32_t len, uint32_t max_len)
{
    char *dst = len <= max_len ? heap_caps_malloc(len + 1, CAP_WASM_PSRAM_CAPS) : NULL;

    if (dst) {
        memcpy(dst, src, len);
        dst[len] = '\0';
    }
    return dst;
}

static void cap_wasm_log(wasm_exec_env_t env, int32_t level, const char *msg, uint32_t len)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    int n = (int)(len < CAP_WASM_LOG_MAX ? len : CAP_WASM_LOG_MAX);

    if (g_cap_wasm_call.app == app && ++g_cap_wasm_call.logs > CAP_WASM_LOGS_PER_CALL) {
        if (g_cap_wasm_call.logs == CAP_WASM_LOGS_PER_CALL + 1) {
            ESP_LOGW(TAG, "[%s] log limit of %d lines per call reached, dropping the rest",
                     app->name, CAP_WASM_LOGS_PER_CALL);
        }
        return;
    }
    switch (level) {
    case 0:
        ESP_LOGE(TAG, "[%s] %.*s", app->name, n, msg);
        break;
    case 1:
        ESP_LOGW(TAG, "[%s] %.*s", app->name, n, msg);
        break;
    case 2:
        ESP_LOGI(TAG, "[%s] %.*s", app->name, n, msg);
        break;
    default:
        ESP_LOGD(TAG, "[%s] %.*s", app->name, n, msg);
        break;
    }
}

static int32_t cap_wasm_tool_register(wasm_exec_env_t env, const char *name, uint32_t name_len,
                                      const char *desc, uint32_t desc_len,
                                      const char *schema, uint32_t schema_len)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);

    if (!app->initializing) {
        ESP_LOGW(TAG, "[%s] tool_register is only allowed in app_init", app->name);
        return -CAP_WASM_EPERM;
    }
    return cap_wasm_tool_add(app, name, name_len, desc, desc_len, schema, schema_len);
}

static int32_t cap_wasm_tool_result(wasm_exec_env_t env, const char *res, uint32_t len)
{
    cap_wasm_call_t *call = &g_cap_wasm_call;
    size_t n;

    if (call->app != cap_wasm_env_app(env)) {
        return -CAP_WASM_EPERM;
    }
    if (len > CAP_WASM_RESULT_MAX) {
        return -CAP_WASM_E2BIG;
    }
    n = len < call->output_size - 1 ? len : call->output_size - 1;
    memcpy(call->output, res, n);
    call->output[n] = '\0';
    cap_wasm_utf8_sanitize(call->output, n);
    call->result_set = true;
    return 0;
}

/* ---------- Key-value store: one NVS namespace per app ---------- */

static bool cap_wasm_kv_key(const char *key, uint32_t len, char out[CAP_WASM_KV_KEY_MAX + 1])
{
    if (len == 0 || len > CAP_WASM_KV_KEY_MAX) {
        return false;
    }
    memcpy(out, key, len);
    out[len] = '\0';
    return strspn(out, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == len;
}

static int32_t cap_wasm_kv_errno(esp_err_t err)
{
    switch (err) {
    case ESP_ERR_NVS_NOT_FOUND:
        return -CAP_WASM_ENOENT;
    case ESP_ERR_NVS_NOT_ENOUGH_SPACE:
        return -CAP_WASM_ENOSPC;
    case ESP_ERR_NO_MEM:
        return -CAP_WASM_ENOMEM;
    default:
        return -CAP_WASM_EIO;
    }
}

static size_t cap_wasm_kv_count(const char *ns)
{
    nvs_iterator_t it = NULL;
    size_t count = 0;
    esp_err_t err = nvs_entry_find(NVS_DEFAULT_PART_NAME, ns, NVS_TYPE_ANY, &it);

    while (err == ESP_OK) {
        count++;
        err = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    return count;
}

static int32_t cap_wasm_kv_get(wasm_exec_env_t env, const char *key, uint32_t key_len,
                               char *out, uint32_t out_cap)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    char k[CAP_WASM_KV_KEY_MAX + 1];
    nvs_handle_t h;
    size_t len = 0;
    esp_err_t err;

    if (!cap_wasm_kv_key(key, key_len, k)) {
        return -CAP_WASM_EINVAL;
    }
    err = nvs_open(app->nvs_ns, NVS_READONLY, &h);
    if (err != ESP_OK) {
        return cap_wasm_kv_errno(err);
    }
    err = nvs_get_blob(h, k, NULL, &len);
    if (err == ESP_OK && len > out_cap) {
        nvs_close(h);
        return -CAP_WASM_ENOBUFS;
    }
    if (err == ESP_OK) {
        err = nvs_get_blob(h, k, out, &len);
    }
    nvs_close(h);
    return err == ESP_OK ? (int32_t)len : cap_wasm_kv_errno(err);
}

static int32_t cap_wasm_kv_write(cap_wasm_app_t *app, const char *key, uint32_t key_len,
                                 const char *val, uint32_t val_len, bool del)
{
    char k[CAP_WASM_KV_KEY_MAX + 1];
    nvs_handle_t h;
    size_t len = 0;
    esp_err_t err;

    if (!cap_wasm_kv_key(key, key_len, k)) {
        return -CAP_WASM_EINVAL;
    }
    if (val_len > CAP_WASM_KV_VALUE_MAX) {
        return -CAP_WASM_E2BIG;
    }
    /* Bounds flash wear from a looping app. */
    if (g_cap_wasm_call.app == app && ++g_cap_wasm_call.kv_writes > CAP_WASM_KV_WRITES_PER_CALL) {
        return -CAP_WASM_ENOSPC;
    }
    err = nvs_open(app->nvs_ns, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return cap_wasm_kv_errno(err);
    }
    if (del) {
        err = nvs_erase_key(h, k);
    } else {
        if (nvs_get_blob(h, k, NULL, &len) == ESP_ERR_NVS_NOT_FOUND &&
                cap_wasm_kv_count(app->nvs_ns) >= CAP_WASM_KV_MAX_KEYS) {
            nvs_close(h);
            return -CAP_WASM_ENOSPC;
        }
        err = nvs_set_blob(h, k, val, val_len);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err == ESP_OK ? 0 : cap_wasm_kv_errno(err);
}

static int32_t cap_wasm_kv_set(wasm_exec_env_t env, const char *key, uint32_t key_len,
                               const char *val, uint32_t val_len)
{
    return cap_wasm_kv_write(cap_wasm_env_app(env), key, key_len, val, val_len, false);
}

static int32_t cap_wasm_kv_del(wasm_exec_env_t env, const char *key, uint32_t key_len)
{
    return cap_wasm_kv_write(cap_wasm_env_app(env), key, key_len, NULL, 0, true);
}

/* ---------- Settings declared in the manifest, set by the user with /app config ---------- */

static int32_t cap_wasm_config_get(wasm_exec_env_t env, const char *key, uint32_t key_len,
                                   char *out, uint32_t out_cap)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    const cap_wasm_setting_t *s = cap_wasm_manifest_setting(&app->mf, key, key_len);
    char value[CAP_WASM_SETTING_VALUE_MAX + 1];
    bool is_default;
    int32_t len;

    if (!s) {
        return -CAP_WASM_EPERM; /* not declared in this app's manifest */
    }
    len = cap_wasm_cfg_get(app, s, value, sizeof(value), &is_default);
    if (len >= 0 && (uint32_t)len > out_cap) {
        return -CAP_WASM_ENOBUFS;
    }
    if (len >= 0) {
        memcpy(out, value, len);
    }
    return len;
}

/* ---------- HTTP through cap_http_request credential profiles ---------- */

static int32_t cap_wasm_http_errno(esp_err_t err)
{
    switch (err) {
    case ESP_ERR_INVALID_ARG:
        return -CAP_WASM_EINVAL;
    case ESP_ERR_NOT_FOUND:
        return -CAP_WASM_ENOENT;
    case ESP_ERR_INVALID_STATE:
        return -CAP_WASM_EPERM;
    case ESP_ERR_NO_MEM:
        return -CAP_WASM_ENOMEM;
    case ESP_ERR_TIMEOUT:
        return -CAP_WASM_ETIMEDOUT;
    case ESP_ERR_NOT_SUPPORTED:
        return -CAP_WASM_ENOTSUP;
    default:
        return -CAP_WASM_EIO;
    }
}

static int32_t cap_wasm_http_profile_request(wasm_exec_env_t env,
                                             const char *profile, uint32_t profile_len,
                                             const char *method, uint32_t method_len,
                                             const char *url, uint32_t url_len,
                                             const char *headers, uint32_t headers_len,
                                             const char *body, uint32_t body_len)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    cap_wasm_call_t *call = &g_cap_wasm_call;
    char *p = cap_wasm_strndup(profile, profile_len, CAP_WASM_ARG_MAX);
    char *m = cap_wasm_strndup(method, method_len, CAP_WASM_ARG_MAX);
    char *u = cap_wasm_strndup(url, url_len, CAP_WASM_ARG_MAX);
    char *h = cap_wasm_strndup(headers, headers_len, CAP_WASM_HEADERS_MAX);
    char *b = cap_wasm_strndup(body, body_len, CAP_WASM_BODY_MAX);
    int status = 0;
    int32_t ret;
    esp_err_t err;

    call->resp_len = call->resp_off = 0;
    if (call->app != app) {
        ret = -CAP_WASM_EPERM; /* needs the originating tool call's context */
    } else if (!p || !m || !u || !h || !b) {
        ret = profile_len > CAP_WASM_ARG_MAX || method_len > CAP_WASM_ARG_MAX || url_len > CAP_WASM_ARG_MAX ||
              headers_len > CAP_WASM_HEADERS_MAX || body_len > CAP_WASM_BODY_MAX ?
              -CAP_WASM_E2BIG : -CAP_WASM_ENOMEM;
    } else if (!cap_wasm_manifest_allows_profile(&app->mf, p)) {
        ESP_LOGW(TAG, "[%s] http profile '%s' is not in the manifest", app->name, p);
        ret = -CAP_WASM_EPERM;
    } else if (!call->resp &&
               !(call->resp = heap_caps_malloc(CAP_WASM_RESPONSE_MAX + 1, CAP_WASM_PSRAM_CAPS))) {
        ret = -CAP_WASM_ENOMEM;
    } else {
        cap_wasm_budget_pause(true);
        err = cap_http_request_profile_call(p, m, u, h, b, CAP_WASM_RESPONSE_MAX, call->ctx, &status,
                                            call->resp, CAP_WASM_RESPONSE_MAX + 1);
        cap_wasm_budget_pause(false);
        call->resp_len = strlen(call->resp);
        ret = err == ESP_OK ? status : cap_wasm_http_errno(err);
        ESP_LOGI(TAG, "[%s] http %s %s %.96s -> %" PRId32 " (%u bytes)", app->name, p, m, u, ret,
                 (unsigned)call->resp_len);
    }
    heap_caps_free(p);
    heap_caps_free(m);
    heap_caps_free(u);
    heap_caps_free(h);
    heap_caps_free(b);
    return ret;
}

static int32_t cap_wasm_http_response_read(wasm_exec_env_t env, char *out, uint32_t out_cap)
{
    cap_wasm_call_t *call = &g_cap_wasm_call;
    size_t n;

    if (call->app != cap_wasm_env_app(env)) {
        return -CAP_WASM_EPERM;
    }
    if (!call->resp) {
        return 0;
    }
    n = call->resp_len - call->resp_off;
    n = n < out_cap ? n : out_cap;
    memcpy(out, call->resp + call->resp_off, n);
    call->resp_off += n;
    return (int32_t)n;
}

/* ---------- Telegram confirmation ---------- */

static int32_t cap_wasm_confirm(wasm_exec_env_t env, const char *text, uint32_t text_len)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    const claw_cap_call_context_t *ctx = g_cap_wasm_call.ctx;

    if (g_cap_wasm_call.app != app) {
        return -CAP_WASM_EPERM;
    }
    if (text_len > CAP_WASM_CONFIRM_TEXT_MAX) {
        return -CAP_WASM_E2BIG;
    }
    /* Same rule as http_request mutations: only for work from an allowed Telegram chat. */
    const char *chat = cap_im_tg_confirm_chat(ctx);

    if (!chat) {
        return -CAP_WASM_ENOTSUP;
    }
#if CONFIG_APP_CLAW_CAP_IM_TG
    static const char *const labels[] = {"✅ Ja", "❌ Abbrechen"};
    const size_t html_size = 288 + CAP_WASM_APP_NAME_MAX + 5 * CAP_WASM_CONFIRM_TEXT_MAX;
    char *html = heap_caps_malloc(html_size, CAP_WASM_PSRAM_CAPS);
    size_t len;
    int choice = -1;
    int64_t message_id = 0;
    esp_err_t err;

    if (!html) {
        return -CAP_WASM_ENOMEM;
    }
    len = (size_t)snprintf(html, html_size, "<b>App %s bittet um Bestätigung</b>\n", app->name);
    for (uint32_t i = 0; i < text_len; i++) {
        const char *entity = text[i] == '&' ? "&amp;" : text[i] == '<' ? "&lt;" : text[i] == '>' ? "&gt;" : NULL;

        if (entity) {
            len += strlcpy(html + len, entity, html_size - len);
        } else {
            html[len++] = text[i];
        }
    }
    html[len] = '\0';
    len = cap_im_tg_confirm_note(ctx, html, html_size);

    cap_wasm_budget_pause(true);
    err = cap_im_tg_confirm(chat, html, labels, 2, CAP_WASM_CONFIRM_TIMEOUT_MS, &choice, &message_id);
    if (err == ESP_OK) {
        snprintf(html + len, html_size - len, "\n\n<b>%s</b>",
                 choice == 0 ? "✅ bestätigt" : choice < 0 ? "⌛ Zeitüberschreitung" : "❌ abgelehnt");
        cap_im_tg_edit_message(chat, message_id, html);
    }
    cap_wasm_budget_pause(false);
    heap_caps_free(html);
    ESP_LOGI(TAG, "[%s] confirm -> %s", app->name, err != ESP_OK ? esp_err_to_name(err) :
             choice == 0 ? "confirmed" : choice < 0 ? "timeout" : "rejected");
    if (err != ESP_OK) {
        return -CAP_WASM_EIO;
    }
    return choice == 0 ? 0 : choice < 0 ? -CAP_WASM_ETIMEDOUT : -CAP_WASM_ECANCELED;
#else
    return -CAP_WASM_ENOTSUP;
#endif
}

/* ---------- Timer and Telegram notifications ---------- */

static int32_t cap_wasm_timer_set_native(wasm_exec_env_t env, int32_t interval_s)
{
    return cap_wasm_timer_set(cap_wasm_env_app(env), interval_s);
}

esp_err_t cap_wasm_send_allowed(const char *text)
{
#if CONFIG_APP_CLAW_CAP_IM_TG
    return cap_im_tg_send_text_to_allowed(text);
#else
    (void)text;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

/* Sends "📣 <app>: <text>" to the allowed Telegram users, at most CAP_WASM_NOTIFY_PER_HOUR per app. */
static int32_t cap_wasm_notify(wasm_exec_env_t env, const char *text, uint32_t text_len)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000);
    const size_t size = CAP_WASM_NOTIFY_MAX + CAP_WASM_APP_NAME_MAX + 16;
    char *msg;
    size_t len;
    esp_err_t err;

    if (g_cap_wasm_call.app != app) {
        return -CAP_WASM_EPERM; /* only in tool_call and on_timer, not app_init */
    }
    if (text_len == 0) {
        return -CAP_WASM_EINVAL;
    }
    if (text_len > CAP_WASM_NOTIFY_MAX) {
        return -CAP_WASM_E2BIG;
    }
    if (!app->notify_count || now_s - app->notify_window_s >= 3600) {
        app->notify_window_s = now_s;
        app->notify_count = 0;
    }
    if (app->notify_count >= CAP_WASM_NOTIFY_PER_HOUR) {
        ESP_LOGW(TAG, "[%s] notify: limit of %d messages per hour reached", app->name, CAP_WASM_NOTIFY_PER_HOUR);
        return -CAP_WASM_ENOSPC;
    }
    msg = heap_caps_malloc(size, CAP_WASM_PSRAM_CAPS);
    if (!msg) {
        return -CAP_WASM_ENOMEM;
    }
    /* The app name always leads, so an app cannot pass its text off as a system message. */
    len = (size_t)snprintf(msg, size, "📣 App `%s`:\n", app->name);
    memcpy(msg + len, text, text_len);
    msg[len + text_len] = '\0';
    cap_wasm_utf8_sanitize(msg + len, text_len);
    app->notify_count++;
    cap_wasm_budget_pause(true);
    err = cap_wasm_send_allowed(msg);
    cap_wasm_budget_pause(false);
    heap_caps_free(msg);
    ESP_LOGI(TAG, "[%s] notify (%u bytes) -> %s", app->name, (unsigned)text_len, esp_err_to_name(err));
    if (err == ESP_OK) {
        return 0;
    }
    return err == ESP_ERR_NOT_SUPPORTED || err == ESP_ERR_NOT_FOUND || err == ESP_ERR_INVALID_STATE ?
           -CAP_WASM_ENOTSUP : -CAP_WASM_EIO;
}

/* ---------- ICMP echo ---------- */

typedef struct {
    SemaphoreHandle_t done;
    uint32_t rtt_min;
    uint32_t rtt_max;
    uint32_t rtt_sum;
} cap_wasm_ping_t;

static void cap_wasm_ping_success(esp_ping_handle_t hdl, void *args)
{
    cap_wasm_ping_t *ping = args;
    uint32_t rtt = 0;

    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &rtt, sizeof(rtt));
    ping->rtt_min = rtt < ping->rtt_min ? rtt : ping->rtt_min;
    ping->rtt_max = rtt > ping->rtt_max ? rtt : ping->rtt_max;
    ping->rtt_sum += rtt;
}

static void cap_wasm_ping_end(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    xSemaphoreGive(((cap_wasm_ping_t *)args)->done);
}

static bool cap_wasm_resolve(const char *host, ip_addr_t *out)
{
    struct addrinfo *res = NULL;
    bool ok = false;

    memset(out, 0, sizeof(*out));
    if (ipaddr_aton(host, out)) {
        return true;
    }
    if (getaddrinfo(host, NULL, NULL, &res) != 0 || !res) {
        return false;
    }
    if (res->ai_family == AF_INET) {
        struct in_addr addr4 = ((struct sockaddr_in *)res->ai_addr)->sin_addr;

        inet_addr_to_ip4addr(ip_2_ip4(out), &addr4);
        IP_SET_TYPE(out, IPADDR_TYPE_V4);
        ok = true;
    } else if (res->ai_family == AF_INET6) {
        struct in6_addr addr6 = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;

        inet6_addr_to_ip6addr(ip_2_ip6(out), &addr6);
        IP_SET_TYPE(out, IPADDR_TYPE_V6);
        ok = true;
    }
    freeaddrinfo(res);
    return ok;
}

/* Pings `host` `count` times and writes a JSON summary to out; returns its length or -errno. */
static int32_t cap_wasm_ping(wasm_exec_env_t env, const char *host, uint32_t host_len, int32_t count,
                             char *out, uint32_t out_cap)
{
    cap_wasm_app_t *app = cap_wasm_env_app(env);
    cap_wasm_ping_t ping = { .rtt_min = UINT32_MAX };
    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    esp_ping_callbacks_t cbs = {
        .cb_args = &ping,
        .on_ping_success = cap_wasm_ping_success,
        .on_ping_end = cap_wasm_ping_end,
    };
    esp_ping_handle_t session = NULL;
    char name[CAP_WASM_HOST_NAME_MAX + 1];
    uint32_t sent = 0;
    uint32_t received = 0;
    int len;

    if (g_cap_wasm_call.app != app) {
        return -CAP_WASM_EPERM;
    }
    if (count < 1 || count > CAP_WASM_PING_MAX_COUNT || host_len == 0 || host_len > CAP_WASM_HOST_NAME_MAX) {
        return -CAP_WASM_EINVAL;
    }
    memcpy(name, host, host_len);
    name[host_len] = '\0';
    /* Host names and IPv4/IPv6 literals only; the name is echoed into JSON unescaped. */
    if (strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:") != host_len) {
        return -CAP_WASM_EINVAL;
    }

    cap_wasm_budget_pause(true);
    if (!cap_wasm_resolve(name, &config.target_addr)) {
        cap_wasm_budget_pause(false);
        return -CAP_WASM_ENOENT;
    }
    config.count = (uint32_t)count;
    config.timeout_ms = CAP_WASM_PING_TIMEOUT_MS;
    config.interval_ms = CAP_WASM_PING_INTERVAL_MS;
    ping.done = xSemaphoreCreateBinary();
    if (!ping.done || esp_ping_new_session(&config, &cbs, &session) != ESP_OK || esp_ping_start(session) != ESP_OK) {
        if (session) {
            esp_ping_delete_session(session);
        }
        if (ping.done) {
            vSemaphoreDelete(ping.done);
        }
        cap_wasm_budget_pause(false);
        return -CAP_WASM_EIO;
    }
    /* The session ends by itself after `count` probes of at most timeout_ms each; the callbacks use
     * `ping` on this stack, so wait for the end callback before returning. */
    xSemaphoreTake(ping.done, portMAX_DELAY);
    esp_ping_get_profile(session, ESP_PING_PROF_REQUEST, &sent, sizeof(sent));
    esp_ping_get_profile(session, ESP_PING_PROF_REPLY, &received, sizeof(received));
    esp_ping_delete_session(session);
    vSemaphoreDelete(ping.done);
    cap_wasm_budget_pause(false);

    len = snprintf(out, out_cap, "{\"host\":\"%s\",\"ip\":\"%s\",\"sent\":%" PRIu32 ",\"received\":%" PRIu32,
                   name, ipaddr_ntoa(&config.target_addr), sent, received);
    if (received > 0 && len > 0 && (uint32_t)len < out_cap) {
        len += snprintf(out + len, out_cap - len, ",\"rtt_ms\":{\"min\":%" PRIu32 ",\"avg\":%" PRIu32 ",\"max\":%" PRIu32 "}",
                        ping.rtt_min, ping.rtt_sum / received, ping.rtt_max);
    }
    if (len > 0 && (uint32_t)len < out_cap) {
        len += snprintf(out + len, out_cap - len, "}");
    }
    ESP_LOGI(TAG, "[%s] ping %s: %" PRIu32 "/%" PRIu32 " replies", app->name, name, received, sent);
    return len > 0 && (uint32_t)len < out_cap ? len : -CAP_WASM_ENOBUFS;
}

/* ---------- Misc ---------- */

static int64_t cap_wasm_now_ms(wasm_exec_env_t env)
{
    struct timeval tv;

    (void)env;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int32_t cap_wasm_random(wasm_exec_env_t env, uint8_t *buf, uint32_t len)
{
    (void)env;
    esp_fill_random(buf, len);
    return 0;
}

/* api 2: wall time with its quality (cap_wasm_time_utc_pack layout); -1 when the clock was never set. */
static int32_t cap_wasm_time_utc(wasm_exec_env_t env, uint8_t *out, uint32_t len)
{
    struct timeval tv;
    uint8_t quality;

    (void)env;
    if (len < CAP_WASM_TIME_UTC_LEN) {
        return -CAP_WASM_EINVAL;
    }
    gettimeofday(&tv, NULL);
    quality = cap_wasm_time_quality(tv.tv_sec);
    cap_wasm_time_utc_pack((int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000, quality, out);
    return quality == CAP_WASM_TIME_NONE ? -1 : 0;
}

/* github.com/esp-claw/app-sdk (include/claw.h, tools/manifest_check.py, tools/wasm_check.py) mirrors
 * this host API and its permissions; update it together with this table. */
NativeSymbol g_cap_wasm_natives[] = {
    { "log", cap_wasm_log, "(i*~)", NULL },
    { "tool_register", cap_wasm_tool_register, "(*~*~*~)i", NULL },
    { "tool_result", cap_wasm_tool_result, "(*~)i", NULL },
    { "kv_get", cap_wasm_kv_get, "(*~*~)i", NULL },
    { "kv_set", cap_wasm_kv_set, "(*~*~)i", NULL },
    { "kv_del", cap_wasm_kv_del, "(*~)i", NULL },
    { "config_get", cap_wasm_config_get, "(*~*~)i", NULL },
    { "http_profile_request", cap_wasm_http_profile_request, "(*~*~*~*~*~)i", NULL },
    { "http_response_read", cap_wasm_http_response_read, "(*~)i", NULL },
    { "confirm", cap_wasm_confirm, "(*~)i", NULL },
    { "ping", cap_wasm_ping, "(*~i*~)i", NULL },
    { "timer_set", cap_wasm_timer_set_native, "(i)i", NULL },
    { "notify", cap_wasm_notify, "(*~)i", NULL },
    { "now_ms", cap_wasm_now_ms, "()I", NULL },
    { "random", cap_wasm_random, "(*~)i", NULL },
    { "time_utc", cap_wasm_time_utc, "(*~)i", NULL },
};
const size_t g_cap_wasm_native_count = sizeof(g_cap_wasm_natives) / sizeof(g_cap_wasm_natives[0]);

bool cap_wasm_host_import_perm(const char *name, uint32_t *out_perm, uint16_t *out_api)
{
    /* Imports not listed need no permission and exist since api 1. */
    static const struct {
        const char *name;
        uint32_t perm;
        uint16_t api;
    } perms[] = {
        { "log", CAP_WASM_PERM_LOG, 1 },
        { "kv_get", CAP_WASM_PERM_KV, 1 },
        { "kv_set", CAP_WASM_PERM_KV, 1 },
        { "kv_del", CAP_WASM_PERM_KV, 1 },
        { "http_profile_request", CAP_WASM_PERM_HTTP, 1 },
        { "http_response_read", CAP_WASM_PERM_HTTP, 1 },
        { "confirm", CAP_WASM_PERM_CONFIRM, 1 },
        { "ping", CAP_WASM_PERM_PING, 1 },
        { "timer_set", CAP_WASM_PERM_TIMER, 1 },
        { "notify", CAP_WASM_PERM_NOTIFY, 1 },
        { "time_utc", 0, 2 },
    };

    for (size_t i = 0; i < g_cap_wasm_native_count; i++) {
        if (strcmp(g_cap_wasm_natives[i].symbol, name) == 0) {
            *out_perm = 0;
            *out_api = 1;
            for (size_t j = 0; j < sizeof(perms) / sizeof(perms[0]); j++) {
                if (strcmp(perms[j].name, name) == 0) {
                    *out_perm = perms[j].perm;
                    *out_api = perms[j].api;
                }
            }
            return true;
        }
    }
    return false;
}
