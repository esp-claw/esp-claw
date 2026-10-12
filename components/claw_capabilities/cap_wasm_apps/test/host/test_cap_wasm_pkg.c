/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Host tests for cap_wasm_pkg.c: package formats 1 and 2, the format 2 signature record, the api
 * check. Run with test/host/run.sh. ecapp_vectors.json (shared with esp-claw/app-sdk, written by its
 * tests/make_vectors.py) holds the test key and the expected records and signatures.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cap_wasm_pkg.h"
#include "mbedtls/base64.h"
#include "monocypher-ed25519.h"

static int s_failed;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

/* True when `err` contains `text`; prints the error otherwise. */
#define CHECK_ERR(err, text)                                            \
    do {                                                                \
        if (!strstr((err), (text))) {                                   \
            printf("FAIL %s:%d: error '%s' lacks '%s'\n", __FILE__, __LINE__, (err), (text)); \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

static cJSON *s_vectors;
static uint8_t s_secret[64]; /* Monocypher secret key of the test key (seed + public key) */
static cap_wasm_key_t s_key;
static cap_wasm_key_t s_other;
static char s_err[160];

static const char *vec(const char *section, const char *field)
{
    const char *s = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(s_vectors, section), field));

    if (!s) {
        printf("vector %s.%s missing\n", section, field);
        exit(1);
    }
    return s;
}

static size_t unhex(const char *hex, uint8_t *out, size_t size)
{
    size_t len = strlen(hex) / 2;

    if (len > size) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned v;

        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
    }
    return len;
}

static void b64(const uint8_t *data, size_t len, char *out, size_t size)
{
    size_t n = 0;

    if (mbedtls_base64_encode((unsigned char *)out, size, &n, data, len) != 0) {
        out[0] = '\0';
    }
}

/* An .ecapp with the three entries in the standard order. */
static size_t pack(uint8_t fmt, const char *manifest, const uint8_t *wasm, size_t wasm_len, const char *sig,
                   uint8_t *out, size_t size)
{
    const struct {
        const char *name;
        const uint8_t *data;
        size_t len;
    } entries[] = {
        {"manifest.json", (const uint8_t *)manifest, strlen(manifest)},
        {"app.wasm", wasm, wasm_len},
        {"signature.json", (const uint8_t *)sig, strlen(sig)},
    };
    size_t off = 8;

    memcpy(out, "ECAP", 4);
    out[4] = fmt;
    out[5] = 3;
    out[6] = out[7] = 0;
    for (size_t i = 0; i < 3; i++) {
        size_t name_len = strlen(entries[i].name);

        if (off + 5 + name_len + entries[i].len > size) {
            return 0;
        }
        out[off++] = (uint8_t)name_len;
        memcpy(out + off, entries[i].name, name_len);
        off += name_len;
        for (int b = 0; b < 4; b++) {
            out[off++] = (uint8_t)(entries[i].len >> (8 * b));
        }
        memcpy(out + off, entries[i].data, entries[i].len);
        off += entries[i].len;
    }
    return off;
}

/* signature.json of format 2 for the given identity (which may differ from the manifest on purpose). */
static void sig_v2(uint16_t api, const char *name, const char *version, const char *manifest,
                   const uint8_t *wasm, size_t wasm_len, char *out, size_t size)
{
    uint8_t manifest_sha[CAP_WASM_SHA_LEN];
    uint8_t wasm_sha[CAP_WASM_SHA_LEN];
    uint8_t record[CAP_WASM_SIG_V2_MAX];
    uint8_t sig[64];
    char sig_b64[96];
    size_t len;

    cap_wasm_sha256((const uint8_t *)manifest, strlen(manifest), manifest_sha);
    cap_wasm_sha256(wasm, wasm_len, wasm_sha);
    len = cap_wasm_sig_record(api, name, version, manifest_sha, wasm_sha, record, sizeof(record));
    crypto_ed25519_sign(sig, s_secret, record, len);
    b64(sig, sizeof(sig), sig_b64, sizeof(sig_b64));
    snprintf(out, size, "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"sdk\":2,\"sig\":\"%s\"}", s_key.key_id, sig_b64);
}

static void sig_v1(const char *name, const char *version, const char *manifest, const uint8_t *wasm, size_t wasm_len,
                   char *out, size_t size)
{
    char manifest_hex[CAP_WASM_SHA_HEX_LEN + 1];
    char wasm_hex[CAP_WASM_SHA_HEX_LEN + 1];
    char canonical[320];
    uint8_t sig[64];
    char sig_b64[96];
    size_t len;

    cap_wasm_sha256_hex((const uint8_t *)manifest, strlen(manifest), manifest_hex);
    cap_wasm_sha256_hex(wasm, wasm_len, wasm_hex);
    len = cap_wasm_sig_canonical(name, version, manifest_hex, wasm_hex, canonical, sizeof(canonical));
    crypto_ed25519_sign(sig, s_secret, (const uint8_t *)canonical, len);
    b64(sig, sizeof(sig), sig_b64, sizeof(sig_b64));
    snprintf(out, size, "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"sdk\":1,\"signed\":{\"name\":\"%s\",\"version\":\"%s\","
             "\"manifest_sha256\":\"%s\",\"wasm_sha256\":\"%s\"},\"sig\":\"%s\"}", s_key.key_id, name, version,
             manifest_hex, wasm_hex, sig_b64);
}

/* Parses, validates and verifies a package the way the installer does; s_err says why not. */
static bool accept(const uint8_t *buf, size_t len, const cap_wasm_key_t *keys, size_t key_count)
{
    cap_wasm_pkg_t pkg;
    cap_wasm_manifest_t mf;
    char manifest[CAP_WASM_MANIFEST_MAX + 1];
    char sig[CAP_WASM_SIGNATURE_MAX + 1];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];

    if (!cap_wasm_pkg_parse(buf, len, &pkg, s_err, sizeof(s_err))) {
        return false;
    }
    memcpy(manifest, pkg.manifest.data, pkg.manifest.len);
    manifest[pkg.manifest.len] = '\0';
    memcpy(sig, pkg.signature.data, pkg.signature.len);
    sig[pkg.signature.len] = '\0';
    return cap_wasm_manifest_parse(manifest, NULL, &mf, s_err, sizeof(s_err)) && cap_wasm_api_check(&mf, s_err, sizeof(s_err)) &&
           cap_wasm_sig_verify(sig, &mf, pkg.manifest.data, pkg.manifest.len, pkg.wasm.data, pkg.wasm.len, keys,
                               key_count, pkg.format, key_id, s_err, sizeof(s_err)) &&
           strcmp(key_id, keys[0].key_id) == 0;
}

static void test_vectors(void)
{
    const char *manifest = vec("sig_v2", "manifest");
    uint8_t wasm[64];
    size_t wasm_len = unhex(vec("sig_v2", "wasm_hex"), wasm, sizeof(wasm));
    uint8_t manifest_sha[CAP_WASM_SHA_LEN];
    uint8_t wasm_sha[CAP_WASM_SHA_LEN];
    uint8_t expected[CAP_WASM_SIG_V2_MAX];
    uint8_t record[CAP_WASM_SIG_V2_MAX];
    uint8_t sig[64];
    char hex[CAP_WASM_SHA_HEX_LEN + 1];
    char sig_b64[96];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
    cap_wasm_manifest_t mf;
    size_t len;

    CHECK(cap_wasm_key_parse(vec("key", "pub_b64"), &s_key) && strcmp(s_key.key_id, vec("key", "key_id")) == 0);
    CHECK(unhex(vec("key", "pub_hex"), expected, sizeof(expected)) == 32 && memcmp(expected, s_key.pub, 32) == 0);
    CHECK(memcmp(s_secret + 32, s_key.pub, 32) == 0); /* the seed derives the vector's public key */

    cap_wasm_sha256_hex((const uint8_t *)manifest, strlen(manifest), hex);
    CHECK(strcmp(hex, vec("sig_v2", "manifest_sha256")) == 0);
    cap_wasm_sha256_hex(wasm, wasm_len, hex);
    CHECK(strcmp(hex, vec("sig_v2", "wasm_sha256")) == 0);

    cap_wasm_sha256((const uint8_t *)manifest, strlen(manifest), manifest_sha);
    cap_wasm_sha256(wasm, wasm_len, wasm_sha);
    len = cap_wasm_sig_record(2, "hello", "1.2.3", manifest_sha, wasm_sha, record, sizeof(record));
    CHECK(len == 13 + 1 + 2 + 1 + 5 + 1 + 5 + 64);
    CHECK(unhex(vec("sig_v2", "record_hex"), expected, sizeof(expected)) == len && memcmp(record, expected, len) == 0);
    CHECK(memcmp(record, "ecapp-sig-v2\0\x02\x02\x00\x05hello\x05" "1.2.3", 27) == 0);
    /* Ed25519 is deterministic: signing the record reproduces the vector's signature. */
    crypto_ed25519_sign(sig, s_secret, record, len);
    b64(sig, sizeof(sig), sig_b64, sizeof(sig_b64));
    CHECK(strcmp(sig_b64, vec("sig_v2", "sig_b64")) == 0);

    CHECK(cap_wasm_manifest_parse(manifest, NULL, &mf, s_err, sizeof(s_err)) && mf.has_api && mf.api == 2);
    CHECK(cap_wasm_sig_verify(vec("sig_v2", "signature_json"), &mf, (const uint8_t *)manifest, strlen(manifest), wasm,
                              wasm_len, &s_key, 1, 2, key_id, s_err, sizeof(s_err)));
    CHECK(cap_wasm_sig_verify(vec("sig_v2", "signature_json"), &mf, (const uint8_t *)manifest, strlen(manifest), wasm,
                              wasm_len, &s_key, 1, 0, key_id, s_err, sizeof(s_err)));
    CHECK(cap_wasm_sig_verify(vec("sig_v1", "signature_json"), &mf, (const uint8_t *)manifest, strlen(manifest), wasm,
                              wasm_len, &s_key, 1, 1, key_id, s_err, sizeof(s_err)));
    CHECK(strcmp(key_id, s_key.key_id) == 0);
}

static void test_packages(void)
{
    static const char manifest[] = "{\"name\":\"hello\",\"version\":\"1.2.3\",\"api\":1}";
    static const char manifest_v1[] = "{\"name\":\"hello\",\"version\":\"1.2.3\"}";
    static const uint8_t wasm[] = "\0asm\1\0\0\0";
    char sig[CAP_WASM_SIGNATURE_MAX];
    uint8_t pkg[1024];
    uint8_t tampered[1024];
    size_t len;
    cap_wasm_pkg_t parsed;

    /* Format 1, with and without "api" in the manifest. */
    sig_v1("hello", "1.2.3", manifest_v1, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(1, manifest_v1, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(accept(pkg, len, &s_key, 1));
    CHECK(cap_wasm_pkg_parse(pkg, len, &parsed, s_err, sizeof(s_err)) && parsed.format == 1);
    sig_v1("hello", "1.2.3", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(1, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(accept(pkg, len, &s_key, 1));
    CHECK(!accept(pkg, len, &s_other, 1));
    CHECK_ERR(s_err, "untrusted key");
    /* A format 1 signature in a format 2 container and vice versa. */
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "signature format 1 in a format 2 package");

    /* Format 2. */
    sig_v2(1, "hello", "1.2.3", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(accept(pkg, len, &s_key, 1));
    CHECK(cap_wasm_pkg_parse(pkg, len, &parsed, s_err, sizeof(s_err)) && parsed.format == 2);
    CHECK(!accept(pkg, len, &s_other, 1));
    CHECK_ERR(s_err, "untrusted key");
    len = pack(1, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "signature format 2 in a format 1 package");
    len = pack(3, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "not an .ecapp package");

    /* Any change to the signed bytes is rejected: manifest, wasm, and the identity in the record. */
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    memcpy(tampered, pkg, len);
    tampered[8 + 1 + 13 + 4 + 2] = ' '; /* inside manifest.json: {" -> {  */
    CHECK(!accept(tampered, len, &s_key, 1));
    memcpy(tampered, pkg, len);
    tampered[len - strlen(sig) - (1 + 14 + 4) - sizeof(wasm) + 4] ^= 1; /* inside app.wasm */
    CHECK(!accept(tampered, len, &s_key, 1));
    CHECK_ERR(s_err, "invalid signature");
    sig_v2(1, "hallo", "1.2.3", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "invalid signature");
    sig_v2(1, "hello", "1.2.4", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "invalid signature");
    sig_v2(2, "hello", "1.2.3", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "invalid signature");

    /* Format 2 needs "api"; a "signed" object is unknown in format 2; sdk 3 is unsupported. */
    sig_v2(1, "hello", "1.2.3", manifest_v1, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest_v1, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "needs \"api\"");
    snprintf(sig, sizeof(sig), "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"sdk\":2,\"signed\":{},\"sig\":\"\"}", s_key.key_id);
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "unknown signature key 'signed'");
    snprintf(sig, sizeof(sig), "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"sdk\":3,\"sig\":\"\"}", s_key.key_id);
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(!accept(pkg, len, &s_key, 1));
    CHECK_ERR(s_err, "unsupported sdk version");
}

static void test_api(void)
{
    static const char *const bad[] = {
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":0}",
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":65536}",
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":\"1\"}",
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":1.5}",
        "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":true}",
    };
    char manifest[96];
    cap_wasm_manifest_t mf;

    CHECK(cap_wasm_manifest_parse("{\"name\":\"a\",\"version\":\"1.0.0\"}", NULL, &mf, s_err, sizeof(s_err)));
    CHECK(!mf.has_api && mf.api == 1 && cap_wasm_api_check(&mf, s_err, sizeof(s_err)));
    CHECK(cap_wasm_manifest_parse("{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":65535}", NULL, &mf, s_err, sizeof(s_err)));
    CHECK(mf.has_api && mf.api == 65535);
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        if (cap_wasm_manifest_parse(bad[i], NULL, &mf, s_err, sizeof(s_err))) {
            printf("FAIL: accepted manifest %s\n", bad[i]);
            s_failed++;
        }
    }
    snprintf(manifest, sizeof(manifest), "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":%d}", CAP_WASM_API_VERSION);
    CHECK(cap_wasm_manifest_parse(manifest, NULL, &mf, s_err, sizeof(s_err)) && cap_wasm_api_check(&mf, s_err, sizeof(s_err)));
    snprintf(manifest, sizeof(manifest), "{\"name\":\"a\",\"version\":\"1.0.0\",\"api\":%d}", CAP_WASM_API_VERSION + 1);
    CHECK(cap_wasm_manifest_parse(manifest, NULL, &mf, s_err, sizeof(s_err)) && !cap_wasm_api_check(&mf, s_err, sizeof(s_err)));
    snprintf(manifest, sizeof(manifest), "needs claw api %d, firmware has %d", CAP_WASM_API_VERSION + 1, CAP_WASM_API_VERSION);
    CHECK(strcmp(s_err, manifest) == 0);
}

static void test_versions(void)
{
    int cmp = 0;

    CHECK(cap_wasm_version_cmp("1.2.0", "1.10.0", &cmp) && cmp < 0);
    CHECK(cap_wasm_version_cmp("1.0.0-rc.1", "1.0.0", &cmp) && cmp < 0);
    CHECK(cap_wasm_version_cmp("1.0.0+b1", "1.0.0+b2", &cmp) && cmp == 0);
    CHECK(!cap_wasm_version_cmp("1.0", "1.0.0", &cmp));
}

int main(void)
{
    FILE *f = fopen("ecapp_vectors.json", "rb");
    char *json = NULL;
    long size;
    uint8_t seed[32];
    uint8_t pub[32];
    uint8_t other_seed[32] = { 1 };
    uint8_t other_secret[64];

    if (!f) {
        printf("cannot open ecapp_vectors.json (run from test/host)\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    json = calloc(1, (size_t)size + 1);
    if (!json || fread(json, 1, (size_t)size, f) != (size_t)size) {
        printf("cannot read ecapp_vectors.json\n");
        return 1;
    }
    fclose(f);
    s_vectors = cJSON_Parse(json);
    free(json);
    if (!s_vectors) {
        printf("ecapp_vectors.json is not valid JSON\n");
        return 1;
    }
    if (unhex(vec("key", "seed_hex"), seed, sizeof(seed)) != 32) {
        printf("bad seed\n");
        return 1;
    }
    crypto_ed25519_key_pair(s_secret, pub, seed); /* wipes the seed */
    crypto_ed25519_key_pair(other_secret, s_other.pub, other_seed);
    cap_wasm_sha256_hex(s_other.pub, 32, s_err);
    memcpy(s_other.key_id, s_err, CAP_WASM_KEY_ID_LEN);
    s_other.key_id[CAP_WASM_KEY_ID_LEN] = '\0';

    test_vectors();
    test_packages();
    test_api();
    test_versions();
    cJSON_Delete(s_vectors);
    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all cap_wasm_pkg tests passed\n");
    return 0;
}
