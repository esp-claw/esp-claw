/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "http_server_auth_core.h"

#include <string.h>

void http_auth_hex(const uint8_t token[HTTP_AUTH_TOKEN_BYTES], char out[HTTP_AUTH_TOKEN_HEX_SIZE])
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < HTTP_AUTH_TOKEN_BYTES; i++) {
        out[2 * i] = digits[token[i] >> 4];
        out[2 * i + 1] = digits[token[i] & 0x0f];
    }
    out[2 * HTTP_AUTH_TOKEN_BYTES] = '\0';
}

static bool http_auth_unhex(const char *hex, uint8_t out[HTTP_AUTH_TOKEN_BYTES])
{
    if (!hex || strlen(hex) != 2 * HTTP_AUTH_TOKEN_BYTES) {
        return false;
    }
    for (size_t i = 0; i < 2 * HTTP_AUTH_TOKEN_BYTES; i++) {
        char c = hex[i];
        int v = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

        if (v < 0) {
            return false;
        }
        out[i / 2] = (uint8_t)(i % 2 ? (out[i / 2] << 4) | v : v);
    }
    return true;
}

/* Constant time: whether and where the tokens differ does not change the run time. */
static bool http_auth_slot_matches(const http_auth_slot_t *slot, const uint8_t token[HTTP_AUTH_TOKEN_BYTES],
                                   int64_t now)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < HTTP_AUTH_TOKEN_BYTES; i++) {
        diff |= slot->token[i] ^ token[i];
    }
    return (diff == 0) & (now < slot->expires);
}

void http_auth_issue_login(http_auth_t *auth, const uint8_t token[HTTP_AUTH_TOKEN_BYTES], int64_t now)
{
    memcpy(auth->login.token, token, HTTP_AUTH_TOKEN_BYTES);
    auth->login.expires = now + HTTP_AUTH_LOGIN_TTL_S;
}

bool http_auth_redeem_login(http_auth_t *auth, const char *login_hex, const uint8_t session[HTTP_AUTH_TOKEN_BYTES],
                            int64_t now)
{
    uint8_t token[HTTP_AUTH_TOKEN_BYTES];
    http_auth_slot_t *slot = &auth->sessions[0];

    if (!http_auth_unhex(login_hex, token) || !http_auth_slot_matches(&auth->login, token, now)) {
        return false;
    }
    memset(&auth->login, 0, sizeof(auth->login));
    for (size_t i = 1; i < HTTP_AUTH_MAX_SESSIONS; i++) {
        if (auth->sessions[i].expires < slot->expires) {
            slot = &auth->sessions[i];
        }
    }
    memcpy(slot->token, session, HTTP_AUTH_TOKEN_BYTES);
    slot->expires = now + HTTP_AUTH_SESSION_TTL_S;
    return true;
}

bool http_auth_session_valid(const http_auth_t *auth, const char *session_hex, int64_t now)
{
    uint8_t token[HTTP_AUTH_TOKEN_BYTES];
    bool valid = false;

    if (!http_auth_unhex(session_hex, token)) {
        return false;
    }
    for (size_t i = 0; i < HTTP_AUTH_MAX_SESSIONS; i++) {
        valid |= http_auth_slot_matches(&auth->sessions[i], token, now);
    }
    return valid;
}

size_t http_auth_session_count(const http_auth_t *auth, int64_t now)
{
    size_t count = 0;

    for (size_t i = 0; i < HTTP_AUTH_MAX_SESSIONS; i++) {
        count += now < auth->sessions[i].expires;
    }
    return count;
}

bool http_auth_cookie(const char *header, const char *name, char *out, size_t out_size)
{
    size_t name_len = strlen(name);

    for (const char *p = header; p && *p; p = strchr(p, ';'), p = p ? p + 1 : NULL) {
        size_t len;

        p += strspn(p, " ");
        if (strncmp(p, name, name_len) != 0 || p[name_len] != '=') {
            continue;
        }
        p += name_len + 1;
        len = strcspn(p, "; ");
        if (len >= out_size) {
            return false;
        }
        memcpy(out, p, len);
        out[len] = '\0';
        return true;
    }
    return false;
}

bool http_auth_ip_in_subnet(uint32_t addr, uint32_t ip, uint32_t netmask)
{
    return ip != 0 && (addr & netmask) == (ip & netmask);
}
