/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host tests for cap_wasm_manifest.c; run with test/host/run.sh. */
#include <stdio.h>
#include <string.h>

#include "cap_wasm_manifest.h"

static int s_failed;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

static cap_wasm_manifest_t s_mf;
static char s_err[160];

static bool parse(const char *json)
{
    return cap_wasm_manifest_parse(json, NULL, &s_mf, s_err, sizeof(s_err));
}

/* `settings_json` is the value of "settings". */
static bool parse_settings(const char *settings_json)
{
    char json[2048];

    snprintf(json, sizeof(json), "{\"name\":\"a\",\"version\":\"1.0.0\",\"settings\":%s}", settings_json);
    return parse(json);
}

static void test_settings_valid(void)
{
    const cap_wasm_setting_t *s;

    CHECK(parse("{\"name\":\"a\",\"version\":\"1.0.0\"}"));
    CHECK(s_mf.setting_count == 0);
    CHECK(parse_settings("[]"));
    CHECK(parse_settings("[{\"key\":\"city\",\"type\":\"string\",\"default\":\"Wien\",\"description\":\"Ort\"},"
                         "{\"key\":\"api_token\",\"type\":\"string\",\"secret\":true},"
                         "{\"key\":\"limit\",\"type\":\"int\",\"default\":-5},"
                         "{\"key\":\"verbose\",\"type\":\"bool\",\"default\":false,\"secret\":false},"
                         "{\"key\":\"abcdefghijklmno\",\"type\":\"int\"}]"));
    CHECK(s_mf.setting_count == 5);
    s = cap_wasm_manifest_setting(&s_mf, "city", 4);
    CHECK(s && s->type == CAP_WASM_SETTING_STRING && s->has_default && strcmp(s->def, "Wien") == 0 &&
          strcmp(s->description, "Ort") == 0 && !s->secret);
    s = cap_wasm_manifest_setting(&s_mf, "api_token", 9);
    CHECK(s && s->secret && !s->has_default);
    s = cap_wasm_manifest_setting(&s_mf, "limit", 5);
    CHECK(s && s->type == CAP_WASM_SETTING_INT && strcmp(s->def, "-5") == 0);
    s = cap_wasm_manifest_setting(&s_mf, "verbose", 7);
    CHECK(s && s->type == CAP_WASM_SETTING_BOOL && strcmp(s->def, "false") == 0);
    /* Lookup compares whole keys only (key_len, not NUL-terminated). */
    CHECK(cap_wasm_manifest_setting(&s_mf, "cityx", 4) != NULL);
    CHECK(cap_wasm_manifest_setting(&s_mf, "cit", 3) == NULL);
    CHECK(cap_wasm_manifest_setting(&s_mf, "nope", 4) == NULL);
    CHECK(parse_settings("[{\"key\":\"a\",\"type\":\"int\",\"default\":2147483647},"
                         "{\"key\":\"b\",\"type\":\"int\",\"default\":-2147483648},"
                         "{\"key\":\"c\",\"type\":\"int\"},{\"key\":\"d\",\"type\":\"int\"},"
                         "{\"key\":\"e\",\"type\":\"int\"},{\"key\":\"f\",\"type\":\"int\"},"
                         "{\"key\":\"g\",\"type\":\"int\"},{\"key\":\"h\",\"type\":\"int\"}]"));
    CHECK(s_mf.setting_count == 8 && strcmp(s_mf.settings[1].def, "-2147483648") == 0);
}

static void test_settings_invalid(void)
{
    static const char *const bad[] = {
        "{}", "[1]", "[{}]",
        "[{\"type\":\"int\"}]",                                         /* no key */
        "[{\"key\":\"a\"}]",                                            /* no type */
        "[{\"key\":\"a\",\"type\":\"float\"}]",
        "[{\"key\":\"A\",\"type\":\"int\"}]",
        "[{\"key\":\"1a\",\"type\":\"int\"}]",
        "[{\"key\":\"a-b\",\"type\":\"int\"}]",
        "[{\"key\":\"_timer\",\"type\":\"int\"}]",                      /* '_' is firmware state */
        "[{\"key\":\"abcdefghijklmnop\",\"type\":\"int\"}]",            /* 16 chars */
        "[{\"key\":\"a\",\"type\":\"int\"},{\"key\":\"a\",\"type\":\"bool\"}]",
        "[{\"key\":\"a\",\"type\":\"int\",\"extra\":1}]",
        "[{\"key\":\"a\",\"type\":\"int\",\"secret\":1}]",
        "[{\"key\":\"a\",\"type\":\"string\",\"secret\":true,\"default\":\"x\"}]",
        "[{\"key\":\"a\",\"type\":\"int\",\"default\":\"5\"}]",
        "[{\"key\":\"a\",\"type\":\"int\",\"default\":1.5}]",
        "[{\"key\":\"a\",\"type\":\"int\",\"default\":2147483648}]",
        "[{\"key\":\"a\",\"type\":\"bool\",\"default\":1}]",
        "[{\"key\":\"a\",\"type\":\"string\",\"default\":5}]",
        "[{\"key\":\"a\",\"type\":\"string\",\"default\":\"\"}]",
        "[{\"key\":\"a\",\"type\":\"string\",\"default\":\"a\\nb\"}]",
        "[{\"key\":\"a\",\"type\":\"string\",\"default\":"
        "\"12345678901234567890123456789012345678901234567890123456789012345\"}]", /* 65 bytes */
        "[{\"key\":\"a\",\"type\":\"int\",\"description\":"
        "\"12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901\"}]",
        "[{\"key\":\"a\",\"type\":\"int\"},{\"key\":\"b\",\"type\":\"int\"},{\"key\":\"c\",\"type\":\"int\"},"
        "{\"key\":\"d\",\"type\":\"int\"},{\"key\":\"e\",\"type\":\"int\"},{\"key\":\"f\",\"type\":\"int\"},"
        "{\"key\":\"g\",\"type\":\"int\"},{\"key\":\"h\",\"type\":\"int\"},{\"key\":\"i\",\"type\":\"int\"}]",
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (parse_settings(bad[i])) {
            printf("FAIL: accepted settings %s\n", bad[i]);
            s_failed++;
        }
    }
}

static void test_normalize(void)
{
    cap_wasm_setting_t str = { .type = CAP_WASM_SETTING_STRING };
    cap_wasm_setting_t num = { .type = CAP_WASM_SETTING_INT };
    cap_wasm_setting_t flag = { .type = CAP_WASM_SETTING_BOOL };
    char out[CAP_WASM_SETTING_VALUE_MAX + 1];
    char big[CAP_WASM_SETTING_VALUE_MAX + 2];

    CHECK(cap_wasm_setting_normalize(&str, "hello world", out, sizeof(out)) && strcmp(out, "hello world") == 0);
    CHECK(cap_wasm_setting_normalize(&str, "Grüße", out, sizeof(out)) && strcmp(out, "Grüße") == 0);
    CHECK(!cap_wasm_setting_normalize(&str, "", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&str, "a\tb", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&str, "a\x7f", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&str, "\xff\xfe", out, sizeof(out)));
    memset(big, 'x', CAP_WASM_SETTING_VALUE_MAX);
    big[CAP_WASM_SETTING_VALUE_MAX] = '\0';
    CHECK(cap_wasm_setting_normalize(&str, big, out, sizeof(out)));
    big[CAP_WASM_SETTING_VALUE_MAX] = 'x';
    big[CAP_WASM_SETTING_VALUE_MAX + 1] = '\0';
    CHECK(!cap_wasm_setting_normalize(&str, big, out, sizeof(out)));

    CHECK(cap_wasm_setting_normalize(&num, "42", out, sizeof(out)) && strcmp(out, "42") == 0);
    CHECK(cap_wasm_setting_normalize(&num, "-007", out, sizeof(out)) && strcmp(out, "-7") == 0);
    CHECK(cap_wasm_setting_normalize(&num, "2147483647", out, sizeof(out)));
    CHECK(cap_wasm_setting_normalize(&num, "-2147483648", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "2147483648", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, " 1", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "+1", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "1e3", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "0x10", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&num, "1-", out, sizeof(out)));

    CHECK(cap_wasm_setting_normalize(&flag, "ON", out, sizeof(out)) && strcmp(out, "true") == 0);
    CHECK(cap_wasm_setting_normalize(&flag, "yes", out, sizeof(out)) && strcmp(out, "true") == 0);
    CHECK(cap_wasm_setting_normalize(&flag, "1", out, sizeof(out)) && strcmp(out, "true") == 0);
    CHECK(cap_wasm_setting_normalize(&flag, "False", out, sizeof(out)) && strcmp(out, "false") == 0);
    CHECK(cap_wasm_setting_normalize(&flag, "off", out, sizeof(out)) && strcmp(out, "false") == 0);
    CHECK(cap_wasm_setting_normalize(&flag, "0", out, sizeof(out)) && strcmp(out, "false") == 0);
    CHECK(!cap_wasm_setting_normalize(&flag, "maybe", out, sizeof(out)));
    CHECK(!cap_wasm_setting_normalize(&flag, "", out, sizeof(out)));
}

static void test_namespaces(void)
{
    char a[CAP_WASM_NVS_NS_LEN];
    char b[CAP_WASM_NVS_NS_LEN];

    cap_wasm_nvs_namespace("hello", a);
    cap_wasm_cfg_namespace("hello", b);
    CHECK(strcmp(a, "wa_hello") == 0 && strcmp(b, "wc_hello") == 0);
    cap_wasm_nvs_namespace("abcdefghijklmnopqrstuvwx", a);
    cap_wasm_cfg_namespace("abcdefghijklmnopqrstuvwx", b);
    CHECK(strlen(a) == 15 && strlen(b) == 15 && strncmp(a, "wa-abcd", 7) == 0 && strncmp(b, "wc-abcd", 7) == 0 &&
          strcmp(a + 3, b + 3) == 0);
}

int main(void)
{
    test_settings_valid();
    test_settings_invalid();
    test_normalize();
    test_namespaces();
    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all cap_wasm_manifest tests passed\n");
    return 0;
}
