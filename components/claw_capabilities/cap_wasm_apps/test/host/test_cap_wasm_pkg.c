/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Host tests for cap_wasm_pkg.c: package formats 1 and 2, the format 2 signature record, the api
 * check, the version floor and the signed update index. Run with test/host/run.sh.
 * ecapp_vectors.json (shared with esp-claw/app-sdk, written by its
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

static void test_rollback(void)
{
    /* No floor yet, same, higher and pre-release-of-higher versions pass. */
    CHECK(cap_wasm_rollback_check("hello", "1.0.0", "", false, s_err, sizeof(s_err)));
    CHECK(cap_wasm_rollback_check("hello", "1.2.0", "1.2.0", false, s_err, sizeof(s_err)));
    CHECK(cap_wasm_rollback_check("hello", "1.10.0", "1.2.0", false, s_err, sizeof(s_err)));
    CHECK(cap_wasm_rollback_check("hello", "2.0.0-rc.1", "1.2.0", false, s_err, sizeof(s_err)));
    /* Below the floor: refused with the floor and the flag in the message, allowed with the flag. */
    CHECK(!cap_wasm_rollback_check("hello", "1.1.9", "1.2.0", false, s_err, sizeof(s_err)));
    CHECK_ERR(s_err, "hello 1.1.9 is below the version floor 1.2.0");
    CHECK_ERR(s_err, CAP_WASM_DOWNGRADE_FLAG);
    CHECK(!cap_wasm_rollback_check("hello", "1.2.0-rc.1", "1.2.0", false, s_err, sizeof(s_err)));
    CHECK(cap_wasm_rollback_check("hello", "1.1.9", "1.2.0", true, s_err, sizeof(s_err)));
    /* A floor that cannot be compared is not silently ignored. */
    CHECK(!cap_wasm_rollback_check("hello", "1.0.0", "garbage", false, s_err, sizeof(s_err)));
    CHECK_ERR(s_err, "cannot compare");
    CHECK(cap_wasm_rollback_check("hello", "1.0.0", "garbage", true, s_err, sizeof(s_err)));
}

/* index.sig for `index` with the test key; `sig_expires` may differ from the index on purpose. */
static void index_sig(const char *index, int64_t sig_expires, char *out, size_t size)
{
    uint8_t index_sha[CAP_WASM_SHA_LEN];
    uint8_t record[CAP_WASM_INDEX_RECORD_LEN];
    uint8_t sig[64];
    char sig_b64[96];

    cap_wasm_sha256((const uint8_t *)index, strlen(index), index_sha);
    cap_wasm_index_record(index_sha, (uint64_t)sig_expires, record, sizeof(record));
    crypto_ed25519_sign(sig, s_secret, record, sizeof(record));
    b64(sig, sizeof(sig), sig_b64, sizeof(sig_b64));
    snprintf(out, size, "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"expires\":%lld,\"sig\":\"%s\"}", s_key.key_id,
             (long long)sig_expires, sig_b64);
}

static bool index_ok(const char *index, const char *sig, int64_t now, bool synced, int64_t last_issued, const char *name,
                     cap_wasm_index_entry_t *entry)
{
    cap_wasm_index_t info;

    return cap_wasm_index_check(index, strlen(index), sig, &s_key, 1, now, synced, last_issued, name, &info, entry, s_err,
                                sizeof(s_err));
}

static void test_index(void)
{
    const char *index = vec("index_v1", "index_json");
    const char *sig = vec("index_v1", "index_sig");
    const int64_t issued = 1780000000;
    const int64_t expires = 1800000000;
    const int64_t now = 1790000000;
    uint8_t index_sha[CAP_WASM_SHA_LEN];
    uint8_t record[CAP_WASM_INDEX_RECORD_LEN];
    uint8_t expected[CAP_WASM_INDEX_RECORD_LEN];
    uint8_t raw[64];
    char sig_b64[96];
    char own[320];
    char tampered[1024];
    cap_wasm_index_t info;
    cap_wasm_index_entry_t entry;

    /* The record and the signature of the vectors. */
    cap_wasm_sha256((const uint8_t *)index, strlen(index), index_sha);
    CHECK(cap_wasm_index_record(index_sha, (uint64_t)expires, record, sizeof(record)) == 55);
    CHECK(unhex(vec("index_v1", "record_hex"), expected, sizeof(expected)) == 55 && memcmp(record, expected, 55) == 0);
    CHECK(memcmp(record, "ecapp-index-v1\0", 15) == 0 && memcmp(record + 47, "\x00\xd2\x49\x6b\x00\x00\x00\x00", 8) == 0);
    crypto_ed25519_sign(raw, s_secret, record, sizeof(record));
    b64(raw, sizeof(raw), sig_b64, sizeof(sig_b64));
    CHECK(strcmp(sig_b64, vec("index_v1", "sig_b64")) == 0);

    /* Accepted: the entry of the app is returned, the times and key reported. */
    CHECK(cap_wasm_index_check(index, strlen(index), sig, &s_key, 1, now, true, 0, "hello", &info, &entry, s_err,
                               sizeof(s_err)));
    CHECK(info.issued == issued && info.expires == expires && strcmp(info.key_id, s_key.key_id) == 0);
    CHECK(strcmp(entry.name, "hello") == 0 && strcmp(entry.version, "1.2.3") == 0 && entry.size == 250 &&
          strcmp(entry.url, "https://example.com/apps/hello-1.2.3.ecapp") == 0 && strlen(entry.sha256) == 64);
    CHECK(index_ok(index, sig, now, true, issued, "other", &entry) && strcmp(entry.version, "0.9.0") == 0);
    CHECK(index_ok(index, sig, expires, true, 0, NULL, &entry));
    CHECK(!index_ok(index, sig, now, true, 0, "nope", &entry));
    CHECK_ERR(s_err, "no entry for app nope");

    /* Expired, frozen (older than the last accepted), unsynced clock. */
    CHECK(!index_ok(index, sig, expires + 1, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "index expired at 1800000000");
    CHECK(!index_ok(index, sig, now, true, issued + 1, "hello", &entry));
    CHECK_ERR(s_err, "older than the last accepted index");
    CHECK(!index_ok(index, sig, now, false, 0, "hello", &entry));
    CHECK_ERR(s_err, "clock not synced, cannot verify index freshness");

    /* Unsigned, wrong key, tampered index, tampered signature. */
    CHECK(!index_ok(index, "", now, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "not a signature object");
    CHECK(!index_ok(index, "{}", now, true, 0, "hello", &entry));
    CHECK(!cap_wasm_index_check(index, strlen(index), sig, &s_other, 1, now, true, 0, "hello", &info, &entry, s_err,
                                sizeof(s_err)));
    CHECK_ERR(s_err, "untrusted key");
    snprintf(tampered, sizeof(tampered), "%s", index);
    tampered[strlen(tampered) - 3] = '}'; /* "]}\n" -> "]}}" : different bytes, no longer valid JSON either */
    CHECK(!index_ok(tampered, sig, now, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "invalid index signature");
    snprintf(own, sizeof(own), "%s", sig);
    own[strlen(own) - 6] ^= 1;
    CHECK(!index_ok(index, own, now, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "invalid index signature");

    /* A signature over the index with another expires than index.json says. */
    index_sig(index, expires + 1, own, sizeof(own));
    CHECK(!index_ok(index, own, now, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "expires (1800000000) does not match the signed expires (1800000001)");
    index_sig(index, expires, own, sizeof(own));
    CHECK(index_ok(index, own, now, true, 0, "hello", &entry));

    /* Content rules: format, unknown keys, invalid entries. */
    snprintf(tampered, sizeof(tampered), "{\"format\":2,\"issued\":1,\"expires\":%lld,\"apps\":[]}", (long long)expires);
    index_sig(tampered, expires, own, sizeof(own));
    CHECK(!index_ok(tampered, own, now, true, 0, NULL, &entry));
    CHECK_ERR(s_err, "unsupported index format");
    snprintf(tampered, sizeof(tampered), "{\"format\":1,\"issued\":1,\"expires\":%lld,\"apps\":[],\"x\":1}", (long long)expires);
    index_sig(tampered, expires, own, sizeof(own));
    CHECK(!index_ok(tampered, own, now, true, 0, NULL, &entry));
    CHECK_ERR(s_err, "unknown index key 'x'");
    snprintf(tampered, sizeof(tampered), "{\"format\":1,\"issued\":1,\"expires\":%lld,\"apps\":[{\"name\":\"hello\","
             "\"version\":\"1.2.3\",\"url\":\"http://example.com/h.ecapp\",\"sha256\":\"%064d\",\"size\":1}]}",
             (long long)expires, 0);
    index_sig(tampered, expires, own, sizeof(own));
    CHECK(!index_ok(tampered, own, now, true, 0, "hello", &entry));
    CHECK_ERR(s_err, "entry for hello is invalid");
    snprintf(tampered, sizeof(tampered), "{\"format\":1,\"issued\":%lld,\"expires\":%lld,\"apps\":[]}",
             (long long)expires + 1, (long long)expires);
    index_sig(tampered, expires, own, sizeof(own));
    CHECK(!index_ok(tampered, own, now, true, 0, NULL, &entry));
    CHECK_ERR(s_err, "issued first");
}

static void test_index_url(void)
{
    char url[CAP_WASM_INDEX_URL_MAX];

    CHECK(cap_wasm_index_url("https://github.com/esp-claw/app-hello/releases/download/v1.0.1/hello-1.0.1.ecapp", url,
                             sizeof(url)) &&
          strcmp(url, "https://github.com/esp-claw/app-hello/releases/latest/download/index.json") == 0);
    CHECK(cap_wasm_index_url("https://example.com/apps/hello-1.2.3.ecapp", url, sizeof(url)) &&
          strcmp(url, "https://example.com/apps/index.json") == 0);
    CHECK(cap_wasm_index_url("https://example.com/h.ecapp", url, sizeof(url)) &&
          strcmp(url, "https://example.com/index.json") == 0);
    CHECK(!cap_wasm_index_url("http://example.com/apps/h.ecapp", url, sizeof(url)));
    CHECK(!cap_wasm_index_url("https://example.com", url, sizeof(url)));
    CHECK(!cap_wasm_index_url("https://example.com/apps/h.ecapp?token=1", url, sizeof(url)));
    CHECK(!cap_wasm_index_url("", url, sizeof(url)));
    CHECK(!cap_wasm_index_url("https://example.com/apps/h.ecapp", url, 24));
}

static bool parse_key_entry(const char *json, cap_wasm_key_t *out)
{
    cJSON *item = cJSON_Parse(json);
    bool ok = cap_wasm_key_parse_entry(item, out, s_err, sizeof(s_err));

    cJSON_Delete(item);
    return ok;
}

static void test_key_scope(void)
{
    static const char manifest[] = "{\"name\":\"cf_dns\",\"version\":\"1.0.0\",\"api\":1}";
    static const uint8_t wasm[] = "\0asm\1\0\0\0";
    const char *index = vec("index_v1", "index_json");
    const char *index_sig = vec("index_v1", "index_sig");
    cap_wasm_key_t scoped;
    cap_wasm_key_t key;
    cap_wasm_index_t info;
    cap_wasm_index_entry_t entry;
    cap_wasm_fw_sig_t fw;
    char json[256];
    char sig[CAP_WASM_SIGNATURE_MAX];
    char canonical[192];
    char sig_b64[96];
    uint8_t raw[64];
    uint8_t pkg[1024];
    size_t len;

    /* Entries: a plain string is unscoped, an object may carry 1-4 name prefixes. */
    snprintf(json, sizeof(json), "\"%s\"", vec("key", "pub_b64"));
    CHECK(parse_key_entry(json, &key) && key.prefix_count == 0 && strcmp(key.key_id, s_key.key_id) == 0);
    CHECK(cap_wasm_key_allows(&key, "anything"));
    snprintf(json, sizeof(json), "{\"key\":\"%s\"}", vec("key", "pub_b64"));
    CHECK(parse_key_entry(json, &key) && key.prefix_count == 0);
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":[\"cf\",\"hello\"]}", vec("key", "pub_b64"));
    CHECK(parse_key_entry(json, &scoped) && scoped.prefix_count == 2 && memcmp(scoped.pub, s_key.pub, 32) == 0);
    CHECK(cap_wasm_key_allows(&scoped, "cf") && cap_wasm_key_allows(&scoped, "cf_dns") && cap_wasm_key_allows(&scoped, "hello"));
    CHECK(!cap_wasm_key_allows(&scoped, "c") && !cap_wasm_key_allows(&scoped, "xcf") && !cap_wasm_key_allows(&scoped, "other"));
    CHECK(!parse_key_entry("\"not base64!\"", &key));
    CHECK(!parse_key_entry("5", &key));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":[]}", vec("key", "pub_b64"));
    CHECK(!parse_key_entry(json, &key));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":[\"a\",\"b\",\"c\",\"d\",\"e\"]}", vec("key", "pub_b64"));
    CHECK(!parse_key_entry(json, &key));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":[\"Cf\"]}", vec("key", "pub_b64"));
    CHECK(!parse_key_entry(json, &key));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":\"cf\"}", vec("key", "pub_b64"));
    CHECK(!parse_key_entry(json, &key));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"scope\":[\"cf\"]}", vec("key", "pub_b64"));
    CHECK(!parse_key_entry(json, &key));
    CHECK_ERR(s_err, "unknown trusted key field 'scope'");

    /* A package signed by a scoped key: accepted inside the scope, refused outside. */
    sig_v2(1, "cf_dns", "1.0.0", manifest, wasm, sizeof(wasm), sig, sizeof(sig));
    len = pack(2, manifest, wasm, sizeof(wasm), sig, pkg, sizeof(pkg));
    CHECK(accept(pkg, len, &scoped, 1));
    snprintf(json, sizeof(json), "{\"key\":\"%s\",\"apps\":[\"hello\"]}", vec("key", "pub_b64"));
    CHECK(parse_key_entry(json, &scoped));
    CHECK(!accept(pkg, len, &scoped, 1));
    CHECK_ERR(s_err, "not trusted for app cf_dns");

    /* The same for the entries of a signed index, and never firmware. */
    CHECK(cap_wasm_index_check(index, strlen(index), index_sig, &scoped, 1, 1790000000, true, 0, "hello", &info, &entry,
                               s_err, sizeof(s_err)));
    CHECK(!cap_wasm_index_check(index, strlen(index), index_sig, &scoped, 1, 1790000000, true, 0, "other", &info, &entry,
                                s_err, sizeof(s_err)));
    CHECK_ERR(s_err, "not trusted for app other");
    len = cap_wasm_fw_sig_canonical("edge_agent", "1.0.0", 1000, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", canonical, sizeof(canonical));
    crypto_ed25519_sign(raw, s_secret, (const uint8_t *)canonical, len);
    b64(raw, sizeof(raw), sig_b64, sizeof(sig_b64));
    snprintf(sig, sizeof(sig), "{\"alg\":\"ed25519\",\"key_id\":\"%s\",\"version\":\"1.0.0\",\"project\":\"edge_agent\","
             "\"size\":1000,\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"sig\":\"%s\"}",
             s_key.key_id, sig_b64);
    CHECK(cap_wasm_fw_sig_verify(sig, &s_key, 1, &fw, s_err, sizeof(s_err)) && fw.size == 1000);
    CHECK(!cap_wasm_fw_sig_verify(sig, &scoped, 1, &fw, s_err, sizeof(s_err)));
    CHECK_ERR(s_err, "scoped to apps and cannot sign firmware");
}

static void test_time_utc(void)
{
    uint8_t out[CAP_WASM_TIME_UTC_LEN];

    CHECK(cap_wasm_time_quality(0) == CAP_WASM_TIME_NONE);
    CHECK(cap_wasm_time_quality(CAP_WASM_CLOCK_VALID_S - 1) == CAP_WASM_TIME_NONE);
    CHECK(cap_wasm_time_quality(CAP_WASM_CLOCK_VALID_S) == CAP_WASM_TIME_SYNCED);
    CHECK(cap_wasm_time_quality(1790000000) == CAP_WASM_TIME_SYNCED);
    /* 1790000000123 ms = 0x000001A0_C450_6C7B little-endian, then the quality byte. */
    cap_wasm_time_utc_pack(1790000000123LL, CAP_WASM_TIME_SYNCED, out);
    CHECK(memcmp(out, "\x7b\x6c\x50\xc4\xa0\x01\x00\x00\x01", 9) == 0);
    cap_wasm_time_utc_pack(0, CAP_WASM_TIME_NONE, out);
    CHECK(memcmp(out, "\0\0\0\0\0\0\0\0\0", 9) == 0);
    cap_wasm_time_utc_pack(-1, CAP_WASM_TIME_AUTHENTICATED, out);
    CHECK(memcmp(out, "\xff\xff\xff\xff\xff\xff\xff\xff\x02", 9) == 0);
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
    test_rollback();
    test_index();
    test_index_url();
    test_key_scope();
    test_time_utc();
    cJSON_Delete(s_vectors);
    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all cap_wasm_pkg tests passed\n");
    return 0;
}
