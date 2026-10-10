/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Who may use the web UI.
 *
 * - Only peers in the STA or soft-AP subnet get in (checked when the connection opens and per request).
 * - HTTPS (443) serves everything. Unless access is open (below), the UI and /api need a session: an
 *   allowlisted Telegram user sends /web and opens the one-time link, which sets a session cookie
 *   (HttpOnly, Secure, SameSite=Strict). State-changing requests also need an X-Requested-With header.
 *   /dav keeps its own Basic auth.
 * - HTTP (80) redirects to HTTPS, except for requests over the soft-AP while access is open, so the
 *   setup portal keeps working. /dav is refused there.
 * - Access is open while Telegram cannot deliver login links (no bot token or allowlist at boot: first
 *   setup), and over the soft-AP while the STA is down if the AP has a password (Wi-Fi recovery).
 */
#include "http_server_priv.h"

#include <stdio.h>
#include <string.h>

#include "claw_cap.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "http_server_auth_core.h"
#include "lwip/sockets.h"

#define AUTH_COOKIE "claw_session"
#define AUTH_PAGE_HEAD "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">" \
                       "<title>ESP-Claw</title><body style=\"font-family:sans-serif;margin:2em\">"

static const char *TAG = "http_auth";

static http_auth_t s_auth;
static portMUX_TYPE s_auth_mux = portMUX_INITIALIZER_UNLOCKED;

static int64_t auth_now(void)
{
    return esp_timer_get_time() / 1000000;
}

bool http_server_netif_ip(const char *ifkey, esp_netif_ip_info_t *info)
{
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey(ifkey);

    return netif && esp_netif_is_netif_up(netif) && esp_netif_get_ip_info(netif, info) == ESP_OK &&
           info->ip.addr != 0;
}

/* IPv4 address (network order) of the socket's peer or local end; 0 unless IPv4 or IPv4-mapped. */
static uint32_t auth_sock_ip(int fd, bool peer)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    if ((peer ? getpeername(fd, (struct sockaddr *)&addr, &len) : getsockname(fd, (struct sockaddr *)&addr, &len)) != 0) {
        return 0;
    }
    if (addr.ss_family == AF_INET) {
        return ((struct sockaddr_in *)&addr)->sin_addr.s_addr;
    }
#if CONFIG_LWIP_IPV6
    if (addr.ss_family == AF_INET6) {
        const uint32_t *a = ((struct sockaddr_in6 *)&addr)->sin6_addr.un.u32_addr;

        return a[0] == 0 && a[1] == 0 && a[2] == PP_HTONL(0xffff) ? a[3] : 0;
    }
#endif
    return 0;
}

static bool auth_peer_allowed(int fd)
{
    static const char *const ifkeys[] = {"WIFI_STA_DEF", "WIFI_AP_DEF"};
    uint32_t peer = auth_sock_ip(fd, true);
    esp_netif_ip_info_t info;

    for (size_t i = 0; i < sizeof(ifkeys) / sizeof(ifkeys[0]); i++) {
        if (http_server_netif_ip(ifkeys[i], &info) && http_auth_ip_in_subnet(peer, info.ip.addr, info.netmask.addr)) {
            return true;
        }
    }
    return false;
}

static bool auth_via_ap(int fd)
{
    esp_netif_ip_info_t info;

    return http_server_netif_ip("WIFI_AP_DEF", &info) && auth_sock_ip(fd, false) == info.ip.addr;
}

static bool auth_open_access(int fd)
{
    http_server_ctx_t *ctx = http_server_ctx();
    http_server_wifi_status_t wifi = {0};

    return !ctx->login_enabled ||
           (ctx->ap_protected && auth_via_ap(fd) && ctx->services.get_wifi_status(&wifi) == ESP_OK &&
            !wifi.wifi_connected);
}

static bool auth_prefix(const char *uri, const char *prefix)
{
    return strncmp(uri, prefix, strlen(prefix)) == 0;
}

esp_err_t http_server_auth_open(httpd_handle_t hd, int sockfd)
{
    if (auth_peer_allowed(sockfd)) {
        return ESP_OK;
    }
    ESP_LOGW(TAG, "Refused a connection from outside the LAN");
    /* esp_https_server ignores this result for TLS sessions, so close those explicitly. */
    if (httpd_sess_get_transport_ctx(hd, sockfd)) {
        httpd_sess_trigger_close(hd, sockfd);
    }
    return ESP_FAIL;
}

static esp_err_t auth_redirect_https(httpd_req_t *req)
{
    char host[16];
    char *location = malloc(sizeof("https://") + sizeof(host) + strlen(req->uri));
    struct in_addr addr = { .s_addr = auth_sock_ip(httpd_req_to_sockfd(req), false) };
    esp_err_t err;

    if (!location) {
        return httpd_resp_send_500(req);
    }
    inet_ntoa_r(addr, host, sizeof(host));
    sprintf(location, "https://%s%s", host, req->uri);
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", location);
    err = httpd_resp_send(req, NULL, 0);
    free(location);
    return err;
}

static bool auth_session_valid(httpd_req_t *req)
{
    size_t len = httpd_req_get_hdr_value_len(req, "Cookie");
    char *header = len ? malloc(len + 1) : NULL;
    char value[HTTP_AUTH_TOKEN_HEX_SIZE];
    bool valid = header && httpd_req_get_hdr_value_str(req, "Cookie", header, len + 1) == ESP_OK &&
                 http_auth_cookie(header, AUTH_COOKIE, value, sizeof(value));

    free(header);
    if (valid) {
        portENTER_CRITICAL(&s_auth_mux);
        valid = http_auth_session_valid(&s_auth, value, auth_now());
        portEXIT_CRITICAL(&s_auth_mux);
    }
    return valid;
}

/* Runs before every registered handler; user_ctx holds the real handler. */
static esp_err_t auth_handler(httpd_req_t *req)
{
    esp_err_t (*handler)(httpd_req_t *) = (esp_err_t (*)(httpd_req_t *))req->user_ctx;
    int fd = httpd_req_to_sockfd(req);
    bool tls = req->handle == http_server_ctx()->https;

    /* A frame on a WebSocket whose upgrade (the GET) passed here. Frames come with method 0, which is
     * also HTTP_DELETE, hence the socket check. */
    if (req->method != HTTP_GET && httpd_ws_get_fd_info(req->handle, fd) == HTTPD_WS_CLIENT_WEBSOCKET) {
        return handler(req);
    }
    if (!auth_peer_allowed(fd)) {
        return ESP_FAIL;
    }
    if (auth_prefix(req->uri, "/dav")) {
        if (tls) {
            return handler(req);
        }
        httpd_resp_set_status(req, "403 Forbidden");
        return httpd_resp_sendstr(req, "WebDAV is only available over HTTPS (davs://)\n");
    }
    if (!tls && !(auth_via_ap(fd) && auth_open_access(fd))) {
        return auth_redirect_https(req);
    }
    /* CSRF: a cross-site page cannot add this header without a CORS preflight, which is never answered. */
    if (req->method != HTTP_GET && req->method != HTTP_HEAD && httpd_req_get_hdr_value_len(req, "X-Requested-With") == 0) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "X-Requested-With header required");
    }
    if (strcmp(req->uri, "/favicon.ico") == 0 || auth_open_access(fd) || auth_session_valid(req)) {
        return handler(req);
    }
    if (auth_prefix(req->uri, "/ws/")) { /* the upgrade is already answered: just close */
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    if (auth_prefix(req->uri, "/api/")) {
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, "{\"error\":\"login required: send /web to the Telegram bot\"}");
    }
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, AUTH_PAGE_HEAD "<h2>Login required</h2>"
                              "<p>Send <b>/web</b> to the Telegram bot and open the link it replies with.</p>");
}

esp_err_t http_server_register_uri(httpd_handle_t server, const httpd_uri_t *uri)
{
    httpd_uri_t gated = *uri;

    gated.handler = auth_handler;
    gated.user_ctx = (void *)uri->handler;
    return httpd_register_uri_handler(server, &gated);
}

/* GET /login?t=<token> (HTTPS only, not gated): trades the one-time token for a session cookie. */
static esp_err_t login_handler(httpd_req_t *req)
{
    char token[HTTP_AUTH_TOKEN_HEX_SIZE];
    char session_hex[HTTP_AUTH_TOKEN_HEX_SIZE];
    char cookie[sizeof(AUTH_COOKIE) + HTTP_AUTH_TOKEN_HEX_SIZE + 80];
    uint8_t session[HTTP_AUTH_TOKEN_BYTES];
    bool ok;

    if (!auth_peer_allowed(httpd_req_to_sockfd(req))) {
        return ESP_FAIL;
    }
    esp_fill_random(session, sizeof(session));
    ok = http_server_query_get(req, "t", token, sizeof(token)) == ESP_OK;
    portENTER_CRITICAL(&s_auth_mux);
    ok = ok && http_auth_redeem_login(&s_auth, token, session, auth_now());
    portEXIT_CRITICAL(&s_auth_mux);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    if (!ok) {
        ESP_LOGW(TAG, "Login with an invalid or expired link");
        httpd_resp_set_status(req, "403 Forbidden");
        return httpd_resp_sendstr(req, AUTH_PAGE_HEAD "<h2>Link invalid or expired</h2>"
                                  "<p>Send <b>/web</b> to the Telegram bot for a new one.</p>");
    }
    http_auth_hex(session, session_hex);
    snprintf(cookie, sizeof(cookie), AUTH_COOKIE "=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict",
             session_hex, HTTP_AUTH_SESSION_TTL_S);
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    ESP_LOGI(TAG, "Web UI login");
    /* A page instead of a 302: browsers drop SameSite=Strict cookies on redirects that started on
     * another site (the Telegram link), the refresh starts here. */
    esp_err_t err = httpd_resp_sendstr(req, AUTH_PAGE_HEAD "<meta http-equiv=\"refresh\" content=\"0;url=/\">"
                                       "<p>Logged in. <a href=\"/\">Continue</a></p>");
    memset(cookie, 0, sizeof(cookie));
    memset(session_hex, 0, sizeof(session_hex));
    return err;
}

esp_err_t http_server_register_login_routes(httpd_handle_t server)
{
    const httpd_uri_t handler = { .uri = "/login", .method = HTTP_GET, .handler = login_handler };

    return httpd_register_uri_handler(server, &handler);
}

/* Port 80, unregistered paths: the captive portal while access over the soft-AP is open, else HTTPS. */
esp_err_t http_server_http_404_handler(httpd_req_t *req, httpd_err_code_t error)
{
    int fd = httpd_req_to_sockfd(req);
    http_server_wifi_status_t status = {0};
    char location[40];

    if (!auth_peer_allowed(fd)) {
        return ESP_FAIL;
    }
    if (!(auth_via_ap(fd) && auth_open_access(fd))) {
        return auth_redirect_https(req);
    }
    if (http_server_ctx()->services.get_wifi_status(&status) != ESP_OK || !status.ap_active) {
        return httpd_resp_send_err(req, error, NULL);
    }
    snprintf(location, sizeof(location), "http://%s/", status.ap_ip && status.ap_ip[0] ? status.ap_ip : "192.168.4.1");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", location);
    httpd_resp_set_hdr(req, "Connection", "close");
    return httpd_resp_send(req, NULL, 0);
}

/* ── /web (Telegram) ─────────────────────────────────────────────────── */

/* Base URL of the device: the STA address, or the soft-AP one while the STA is down. */
static bool web_host(char host[16])
{
    esp_netif_ip_info_t info;

    if (!http_server_netif_ip("WIFI_STA_DEF", &info) && !http_server_netif_ip("WIFI_AP_DEF", &info)) {
        return false;
    }
    esp_ip4addr_ntoa(&info.ip, host, 16);
    return true;
}

static void web_status(char *output, size_t output_size)
{
    http_server_ctx_t *ctx = http_server_ctx();
    esp_netif_ip_info_t info;
    char sta[16] = "";
    char ap[16] = "";
    char names[sizeof(ctx->cert_names) + 2];
    char pattern[20];
    size_t sessions;
    int len;

    if (http_server_netif_ip("WIFI_STA_DEF", &info)) {
        esp_ip4addr_ntoa(&info.ip, sta, sizeof(sta));
    }
    if (http_server_netif_ip("WIFI_AP_DEF", &info)) {
        esp_ip4addr_ntoa(&info.ip, ap, sizeof(ap));
    }
    portENTER_CRITICAL(&s_auth_mux);
    sessions = http_auth_session_count(&s_auth, auth_now());
    portEXIT_CRITICAL(&s_auth_mux);
    len = snprintf(output, output_size, "Web UI:%s%s%s%s%s\nWebDAV (if enabled): davs://%s/dav/\n"
                   "Login: %s\nActive sessions: %u of %d\nCertificate SHA-256:\n%s\nCertificate for: %s (until %s)",
                   sta[0] ? " https://" : "", sta, ap[0] ? " https://" : "", ap, ap[0] ? " (setup AP)" : "",
                   sta[0] ? sta : ap,
                   ctx->login_enabled ? "via /web" : "off, the UI is open (Telegram was not configured at boot)",
                   (unsigned)sessions, HTTP_AUTH_MAX_SESSIONS, ctx->cert_sha256, ctx->cert_names, ctx->cert_until);
    snprintf(names, sizeof(names), "%s,", ctx->cert_names);
    snprintf(pattern, sizeof(pattern), " %s,", sta);
    if (len > 0 && (size_t)len < output_size && sta[0] && !strstr(names, pattern)) {
        snprintf(output + len, output_size - len, "\nThe certificate does not cover %s: /web cert renew", sta);
    }
}

static esp_err_t web_command_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                     char *output, size_t output_size)
{
    cJSON *input = NULL;
    const char *command = NULL;
    char host[16];
    uint8_t token[HTTP_AUTH_TOKEN_BYTES];
    char token_hex[HTTP_AUTH_TOKEN_HEX_SIZE];
    esp_err_t err = ESP_OK;

    /* Only the Telegram command (allowlisted senders); the agent, Lua and the console never get a link. */
    if (!ctx || ctx->caller != CLAW_CAP_CALLER_SYSTEM || !ctx->source_cap || strcmp(ctx->source_cap, "tg_gateway") != 0) {
        snprintf(output, output_size, "Error: /web is a Telegram command");
        return ESP_ERR_NOT_SUPPORTED;
    }
    input = cJSON_Parse(input_json);
    command = cJSON_GetStringValue(cJSON_GetObjectItem(input, "command"));
    command = command ? command : "";
    if (strcmp(command, "status") == 0) {
        web_status(output, output_size);
    } else if (strcmp(command, "cert renew") == 0) {
        err = http_server_https_start(true);
        if (err == ESP_OK) {
            web_status(output, output_size);
        } else {
            snprintf(output, output_size, "Error: certificate renewal failed (%s)", esp_err_to_name(err));
        }
    } else if (command[0]) {
        snprintf(output, output_size, "Usage:\n/web  One-time login link (5 min)\n/web status  URLs, sessions, "
                 "certificate\n/web cert renew  New certificate for the current IP addresses");
    } else if (!http_server_ctx()->https || !web_host(host)) {
        snprintf(output, output_size, "Error: the HTTPS server is not running");
        err = ESP_ERR_INVALID_STATE;
    } else {
        esp_fill_random(token, sizeof(token));
        portENTER_CRITICAL(&s_auth_mux);
        http_auth_issue_login(&s_auth, token, auth_now());
        portEXIT_CRITICAL(&s_auth_mux);
        http_auth_hex(token, token_hex);
        snprintf(output, output_size, "Login link (valid 5 min, single use):\nhttps://%s/login?t=%s\n\n"
                 "Certificate SHA-256 (compare with the browser warning):\n%s%s",
                 host, token_hex, http_server_ctx()->cert_sha256,
                 http_server_ctx()->login_enabled ? "" : "\n\nLogin is off until a restart: the UI is open.");
        memset(token, 0, sizeof(token));
        memset(token_hex, 0, sizeof(token_hex));
        ESP_LOGI(TAG, "Issued a web UI login link");
    }
    cJSON_Delete(input);
    return err;
}

static const claw_cap_descriptor_t s_web_descriptors[] = {
    {
        .id = "web_command",
        .name = "web_command",
        .family = "system",
        .description = "Handle the /web chat command.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = web_command_execute,
    },
};

static const claw_cap_group_t s_web_group = {
    .group_id = "http_server_web",
    .plugin_name = "http_server",
    .version = "1",
    .descriptors = s_web_descriptors,
    .descriptor_count = sizeof(s_web_descriptors) / sizeof(s_web_descriptors[0]),
};

esp_err_t http_server_register_web_command(void)
{
    return claw_cap_register_group(&s_web_group);
}
