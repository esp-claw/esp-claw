/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host tests for http_server_auth_core.c; run with test/host/run.sh. */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "http_server_auth_core.h"

static int s_failed;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

static void token(uint8_t out[HTTP_AUTH_TOKEN_BYTES], uint8_t seed)
{
    for (size_t i = 0; i < HTTP_AUTH_TOKEN_BYTES; i++) {
        out[i] = (uint8_t)(seed * 31 + i * 7);
    }
}

static void test_login(void)
{
    http_auth_t auth = {0};
    uint8_t login[HTTP_AUTH_TOKEN_BYTES];
    uint8_t session[HTTP_AUTH_TOKEN_BYTES];
    char login_hex[HTTP_AUTH_TOKEN_HEX_SIZE];
    char session_hex[HTTP_AUTH_TOKEN_HEX_SIZE];
    char upper[HTTP_AUTH_TOKEN_HEX_SIZE];

    token(login, 1);
    token(session, 2);
    http_auth_hex(login, login_hex);
    http_auth_hex(session, session_hex);
    CHECK(strlen(login_hex) == 32);

    /* Nothing issued: an all-zero token must not match the empty slot. */
    CHECK(!http_auth_redeem_login(&auth, "00000000000000000000000000000000", session, 1000));

    http_auth_issue_login(&auth, login, 1000);
    /* Wrong, short, long and non-hex tokens fail and keep the link usable. */
    login_hex[31] ^= 1;
    CHECK(!http_auth_redeem_login(&auth, login_hex, session, 1001));
    login_hex[31] ^= 1;
    CHECK(!http_auth_redeem_login(&auth, "abcd", session, 1001));
    CHECK(!http_auth_redeem_login(&auth, "0123456789abcdef0123456789abcdef0", session, 1001));
    CHECK(!http_auth_redeem_login(&auth, "0123456789abcdef0123456789abcdeg", session, 1001));
    CHECK(!http_auth_redeem_login(&auth, NULL, session, 1001));
    CHECK(http_auth_session_count(&auth, 1001) == 0);

    /* Case-insensitive hex, single use. */
    for (size_t i = 0; i < sizeof(upper); i++) {
        upper[i] = (char)(login_hex[i] >= 'a' && login_hex[i] <= 'f' ? login_hex[i] - 32 : login_hex[i]);
    }
    CHECK(http_auth_redeem_login(&auth, upper, session, 1001));
    CHECK(!http_auth_redeem_login(&auth, login_hex, session, 1002));
    CHECK(http_auth_session_valid(&auth, session_hex, 1002));
    CHECK(http_auth_session_count(&auth, 1002) == 1);

    /* The login link expires after 5 minutes. */
    http_auth_issue_login(&auth, login, 2000);
    CHECK(!http_auth_redeem_login(&auth, login_hex, session, 2000 + HTTP_AUTH_LOGIN_TTL_S));
    http_auth_issue_login(&auth, login, 2000);
    CHECK(http_auth_redeem_login(&auth, login_hex, session, 2000 + HTTP_AUTH_LOGIN_TTL_S - 1));

    /* A new link replaces the pending one. */
    http_auth_issue_login(&auth, login, 3000);
    token(login, 3);
    http_auth_issue_login(&auth, login, 3001);
    CHECK(!http_auth_redeem_login(&auth, login_hex, session, 3002));
}

static void test_sessions(void)
{
    http_auth_t auth = {0};
    uint8_t login[HTTP_AUTH_TOKEN_BYTES];
    uint8_t session[HTTP_AUTH_TOKEN_BYTES];
    char login_hex[HTTP_AUTH_TOKEN_HEX_SIZE];
    char hex[HTTP_AUTH_MAX_SESSIONS + 1][HTTP_AUTH_TOKEN_HEX_SIZE];

    token(login, 9);
    http_auth_hex(login, login_hex);
    for (int i = 0; i <= HTTP_AUTH_MAX_SESSIONS; i++) {
        token(session, (uint8_t)(20 + i));
        http_auth_hex(session, hex[i]);
        http_auth_issue_login(&auth, login, 100 + i);
        CHECK(http_auth_redeem_login(&auth, login_hex, session, 100 + i));
    }
    /* Four slots: the fifth login replaced the oldest session. */
    CHECK(http_auth_session_count(&auth, 200) == HTTP_AUTH_MAX_SESSIONS);
    CHECK(!http_auth_session_valid(&auth, hex[0], 200));
    for (int i = 1; i <= HTTP_AUTH_MAX_SESSIONS; i++) {
        CHECK(http_auth_session_valid(&auth, hex[i], 200));
    }

    /* 12 h lifetime. */
    CHECK(http_auth_session_valid(&auth, hex[1], 101 + HTTP_AUTH_SESSION_TTL_S - 1));
    CHECK(!http_auth_session_valid(&auth, hex[1], 101 + HTTP_AUTH_SESSION_TTL_S));
    CHECK(http_auth_session_count(&auth, 101 + HTTP_AUTH_SESSION_TTL_S) == HTTP_AUTH_MAX_SESSIONS - 1);

    /* Junk session values. */
    CHECK(!http_auth_session_valid(&auth, "", 200));
    CHECK(!http_auth_session_valid(&auth, NULL, 200));
    CHECK(!http_auth_session_valid(&auth, login_hex, 200));
    hex[2][0] = hex[2][0] == '0' ? '1' : '0';
    CHECK(!http_auth_session_valid(&auth, hex[2], 200));
}

static void test_cookie(void)
{
    char out[HTTP_AUTH_TOKEN_HEX_SIZE];

    CHECK(http_auth_cookie("claw_session=abc", "claw_session", out, sizeof(out)) && strcmp(out, "abc") == 0);
    CHECK(http_auth_cookie("a=1; claw_session=def; b=2", "claw_session", out, sizeof(out)) && strcmp(out, "def") == 0);
    CHECK(http_auth_cookie("a=1;claw_session=ghi", "claw_session", out, sizeof(out)) && strcmp(out, "ghi") == 0);
    CHECK(!http_auth_cookie("xclaw_session=abc", "claw_session", out, sizeof(out)));
    CHECK(!http_auth_cookie("claw_sessionx=abc", "claw_session", out, sizeof(out)));
    CHECK(!http_auth_cookie("a=claw_session=abc", "claw_session", out, sizeof(out)));
    CHECK(!http_auth_cookie("", "claw_session", out, sizeof(out)));
    CHECK(!http_auth_cookie("claw_session=0123456789abcdef0123456789abcdef0", "claw_session", out, sizeof(out)));
    CHECK(http_auth_cookie("claw_session=0123456789abcdef0123456789abcdef", "claw_session", out, sizeof(out)));
}

static void test_subnet(void)
{
    uint32_t sta = inet_addr("192.168.1.50");
    uint32_t sta_mask = inet_addr("255.255.255.0");
    uint32_t ap = inet_addr("192.168.4.1");
    uint32_t ap_mask = inet_addr("255.255.255.0");

    CHECK(http_auth_ip_in_subnet(inet_addr("192.168.1.10"), sta, sta_mask));
    CHECK(http_auth_ip_in_subnet(inet_addr("192.168.1.255"), sta, sta_mask));
    CHECK(!http_auth_ip_in_subnet(inet_addr("192.168.2.10"), sta, sta_mask));
    CHECK(!http_auth_ip_in_subnet(inet_addr("8.8.8.8"), sta, sta_mask));
    CHECK(http_auth_ip_in_subnet(inet_addr("192.168.4.2"), ap, ap_mask));
    CHECK(!http_auth_ip_in_subnet(inet_addr("192.168.4.2"), sta, sta_mask));
    CHECK(http_auth_ip_in_subnet(inet_addr("10.20.30.40"), inet_addr("10.0.0.1"), inet_addr("255.0.0.0")));
    /* A down interface (ip 0) and non-IPv4 peers (0) match nothing. */
    CHECK(!http_auth_ip_in_subnet(inet_addr("192.168.1.10"), 0, 0));
    CHECK(!http_auth_ip_in_subnet(0, sta, sta_mask));
    CHECK(!http_auth_ip_in_subnet(0, 0, 0));
}

int main(void)
{
    test_login();
    test_sessions();
    test_cookie();
    test_subnet();
    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all http_server_auth_core tests passed\n");
    return 0;
}
