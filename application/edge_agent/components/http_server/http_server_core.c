/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "http_server_priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "esp_check.h"
#include "esp_heap_caps.h"
#include "esp_https_server.h"
#include "esp_log.h"

static const char *TAG = "http_server";

static http_server_ctx_t s_ctx;

http_server_ctx_t *http_server_ctx(void)
{
    return &s_ctx;
}

esp_err_t http_server_init(const http_server_config_t *config)
{
    if (!config || !config->storage_base_path || config->storage_base_path[0] != '/') {
        return ESP_ERR_INVALID_ARG;
    }
    if (!config->services.load_config || !config->services.save_config || !config->services.get_wifi_status) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_ctx, 0, sizeof(s_ctx));
    strlcpy(s_ctx.storage_base_path, config->storage_base_path, sizeof(s_ctx.storage_base_path));
    s_ctx.services = config->services;
    return ESP_OK;
}

static void http_server_close_fn(httpd_handle_t hd, int sockfd)
{
    (void)hd;
    http_server_webim_ws_fd_remove(sockfd);
    close(sockfd);
}

void http_server_httpd_config(httpd_config_t *config)
{
    config->max_uri_handlers = 32;
    config->max_req_hdr_len = 2048; /* WebDAV clients send long Destination/If/User-Agent headers */
    config->stack_size = 8192;
    config->lru_purge_enable = true;

    uint32_t task_caps = MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT;
#if CONFIG_FREERTOS_TASK_CREATE_ALLOW_EXT_MEM
    if (heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM) >= config->stack_size) {
        task_caps = MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT;
    }
#endif
    config->task_caps = task_caps;

    config->open_fn = http_server_auth_open;
    config->close_fn = http_server_close_fn;
    config->uri_match_fn = httpd_uri_match_wildcard;
}

/* The same handlers on both servers; Web IM (one WebSocket server) and /login only on HTTPS. */
esp_err_t http_server_register_routes(httpd_handle_t server)
{
    bool tls = server == s_ctx.https;

    ESP_RETURN_ON_ERROR(http_server_register_assets_routes(server), TAG, "Failed to register assets routes");
    ESP_RETURN_ON_ERROR(http_server_register_capabilities_routes(server), TAG, "Failed to register capability routes");
    ESP_RETURN_ON_ERROR(http_server_register_lua_modules_routes(server), TAG, "Failed to register Lua module routes");
    ESP_RETURN_ON_ERROR(http_server_register_config_routes(server), TAG, "Failed to register config routes");
    ESP_RETURN_ON_ERROR(http_server_register_status_routes(server), TAG, "Failed to register status routes");
    ESP_RETURN_ON_ERROR(http_server_register_files_routes(server), TAG, "Failed to register files routes");
#if CONFIG_APP_CLAW_LUA_MODULE_HTTP_SERVER
    ESP_RETURN_ON_ERROR(http_server_register_lua_app_routes(server), TAG, "Failed to register Lua app routes");
#endif
    ESP_RETURN_ON_ERROR(http_server_register_wechat_routes(server), TAG, "Failed to register WeChat routes");
    ESP_RETURN_ON_ERROR(http_server_register_webdav_routes(server), TAG, "Failed to register WebDAV routes");
    if (tls) {
        ESP_RETURN_ON_ERROR(http_server_register_webim_routes(server), TAG, "Failed to register Web IM routes");
        ESP_RETURN_ON_ERROR(http_server_register_login_routes(server), TAG, "Failed to register login route");
    }
    return ESP_OK;
}

esp_err_t http_server_start(void)
{
    if (s_ctx.http) {
        return ESP_OK;
    }

    app_config_t *app_config = calloc(1, sizeof(*app_config));
    if (app_config && s_ctx.services.load_config(app_config) == ESP_OK) {
        http_server_webdav_apply_config(app_config);
#if CONFIG_APP_CLAW_CAP_IM_TG
        s_ctx.login_enabled = app_config->tg_bot_token[0] && strpbrk(app_config->tg_allowed_user_ids, "0123456789");
#endif
        s_ctx.ap_protected = app_config->ap_password[0] != '\0';
    }
    free(app_config);

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    http_server_httpd_config(&config);
    config.server_port = 80;
    config.ctrl_port = HTTP_SERVER_CTRL_PORT;
    config.max_open_sockets = 6;

    ESP_RETURN_ON_ERROR(httpd_start(&s_ctx.http, &config), TAG, "Failed to start HTTP server");
    ESP_RETURN_ON_ERROR(http_server_register_routes(s_ctx.http), TAG, "Failed to register HTTP routes");
    ESP_RETURN_ON_ERROR(httpd_register_err_handler(s_ctx.http, HTTPD_404_NOT_FOUND, http_server_http_404_handler),
                        TAG, "Failed to register captive 404 handler");

    /* Without HTTPS the device stays reachable over the soft-AP while access is open. */
    esp_err_t err = http_server_https_start(false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTPS server failed to start: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI(TAG, "Web UI on https (443), login %s; certificate SHA-256 %s",
                 s_ctx.login_enabled ? "with Telegram /web" : "off (Telegram not configured)", s_ctx.cert_sha256);
    }
    return ESP_OK;
}

esp_err_t http_server_stop(void)
{
    if (s_ctx.https && httpd_ssl_stop(s_ctx.https) == ESP_OK) {
        s_ctx.https = NULL;
    }
    if (!s_ctx.http) {
        return ESP_OK;
    }

    esp_err_t err = httpd_stop(s_ctx.http);
    if (err == ESP_OK) {
        s_ctx.http = NULL;
    }
    return err;
}
