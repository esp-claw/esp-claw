/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_netif.h"
#include "http_server.h"

#define HTTP_SERVER_CTRL_PORT         32769
#define HTTP_SERVER_SCRATCH_SIZE      4096
#define HTTP_SERVER_PATH_MAX          256
#define HTTP_SERVER_UPLOAD_MAX_SIZE   (512 * 1024)
#define HTTP_SERVER_TMP_SUFFIX        ".davtmp"

typedef struct {
    httpd_handle_t https; /* 443: UI, API, WebDAV */
    httpd_handle_t http;  /* 80: redirect to HTTPS, or the UI over the soft-AP while access is open */
    char storage_base_path[HTTP_SERVER_PATH_MAX];
    http_server_services_t services;
    bool login_enabled; /* Telegram can deliver /web login links (bot token and allowlist at boot) */
    bool ap_protected;  /* the soft-AP has a password */
    char cert_sha256[96];
    char cert_names[96];
    char cert_until[12];
} http_server_ctx_t;

http_server_ctx_t *http_server_ctx(void);

char *http_server_alloc_scratch_buffer(void);
bool http_server_path_is_safe(const char *path);
void http_server_url_decode_inplace(char *value);
esp_err_t http_server_query_get(httpd_req_t *req, const char *key, char *value, size_t value_size);
esp_err_t http_server_send_embedded_file(httpd_req_t *req,
                                         const uint8_t *start,
                                         const uint8_t *end,
                                         const char *content_type);
void http_server_json_add_string(cJSON *root, const char *key, const char *value);
esp_err_t http_server_send_json_response(httpd_req_t *req, cJSON *root);
esp_err_t http_server_parse_json_body(httpd_req_t *req, cJSON **out_root);
void http_server_json_read_string(cJSON *root, const char *key, char *buffer, size_t buffer_size);
esp_err_t http_server_resolve_storage_path(const char *relative_path, char *full_path, size_t full_path_size);
bool http_server_build_child_relative_path(const char *base_path,
                                           const char *entry_name,
                                           char *out_path,
                                           size_t out_path_size);
int http_server_recv_to_file(httpd_req_t *req, const char *path);
int http_server_replace_file(const char *src, const char *dst);
int http_server_rmdir_recursive(const char *path);

esp_err_t http_server_register_assets_routes(httpd_handle_t server);
esp_err_t http_server_register_capabilities_routes(httpd_handle_t server);
esp_err_t http_server_register_lua_modules_routes(httpd_handle_t server);
esp_err_t http_server_register_config_routes(httpd_handle_t server);
esp_err_t http_server_register_status_routes(httpd_handle_t server);
esp_err_t http_server_register_files_routes(httpd_handle_t server);
#if CONFIG_APP_CLAW_LUA_MODULE_HTTP_SERVER
esp_err_t http_server_register_lua_app_routes(httpd_handle_t server);
#endif
#if CONFIG_APP_CLAW_CAP_WASM_APPS
esp_err_t http_server_register_wasm_apps_routes(httpd_handle_t server);
#endif
esp_err_t http_server_register_wechat_routes(httpd_handle_t server);
esp_err_t http_server_register_webim_routes(httpd_handle_t server);
esp_err_t http_server_register_webdav_routes(httpd_handle_t server);
void http_server_webdav_apply_config(const app_config_t *config);
void http_server_webim_ws_fd_remove(int fd);

void http_server_httpd_config(httpd_config_t *config);
esp_err_t http_server_register_routes(httpd_handle_t server);
/* Registers `uri` behind the access check of http_server_auth.c. */
esp_err_t http_server_register_uri(httpd_handle_t server, const httpd_uri_t *uri);
esp_err_t http_server_register_login_routes(httpd_handle_t server);
esp_err_t http_server_auth_open(httpd_handle_t hd, int sockfd);
esp_err_t http_server_http_404_handler(httpd_req_t *req, httpd_err_code_t error);
/* Address of a Wi-Fi interface ("WIFI_STA_DEF", "WIFI_AP_DEF") while it is up with an IP. */
bool http_server_netif_ip(const char *ifkey, esp_netif_ip_info_t *info);
/* (Re)starts the HTTPS server; `renew` replaces the certificate first. */
esp_err_t http_server_https_start(bool renew);
