/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Login tokens, sessions and the LAN check of the web UI; plain C without ESP-IDF (host tests in test/host). */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define HTTP_AUTH_TOKEN_BYTES    16 /* 128 bit */
#define HTTP_AUTH_TOKEN_HEX_SIZE (2 * HTTP_AUTH_TOKEN_BYTES + 1)
#define HTTP_AUTH_MAX_SESSIONS   4
#define HTTP_AUTH_LOGIN_TTL_S    (5 * 60)
#define HTTP_AUTH_SESSION_TTL_S  (12 * 60 * 60)

typedef struct {
    uint8_t token[HTTP_AUTH_TOKEN_BYTES];
    int64_t expires; /* monotonic seconds; the slot is free once now >= expires */
} http_auth_slot_t;

typedef struct {
    http_auth_slot_t login; /* the one pending login link; a new one replaces it */
    http_auth_slot_t sessions[HTTP_AUTH_MAX_SESSIONS];
} http_auth_t;

void http_auth_hex(const uint8_t token[HTTP_AUTH_TOKEN_BYTES], char out[HTTP_AUTH_TOKEN_HEX_SIZE]);
void http_auth_issue_login(http_auth_t *auth, const uint8_t token[HTTP_AUTH_TOKEN_BYTES], int64_t now);
/* Single use: on success the login token is spent and `session` becomes a session, replacing the oldest
 * one when all slots are taken. */
bool http_auth_redeem_login(http_auth_t *auth, const char *login_hex, const uint8_t session[HTTP_AUTH_TOKEN_BYTES],
                            int64_t now);
bool http_auth_session_valid(const http_auth_t *auth, const char *session_hex, int64_t now);
size_t http_auth_session_count(const http_auth_t *auth, int64_t now);
/* Copies the value of cookie `name` from a Cookie header; false when missing or longer than out_size - 1. */
bool http_auth_cookie(const char *header, const char *name, char *out, size_t out_size);
/* IPv4 addresses in network byte order; an interface with ip 0 matches nothing. */
bool http_auth_ip_in_subnet(uint32_t addr, uint32_t ip, uint32_t netmask);
