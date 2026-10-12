/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_pkg.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "monocypher-ed25519.h"

bool cap_wasm_pkg_parse(const uint8_t *buf, size_t len, cap_wasm_pkg_t *out, char *err, size_t err_size)
{
    static const struct {
        const char *name;
        size_t max;
    } names[] = {
        {"manifest.json", CAP_WASM_MANIFEST_MAX},
        {"app.wasm", CAP_WASM_WASM_MAX},
        {"signature.json", CAP_WASM_SIGNATURE_MAX},
    };
    cap_wasm_blob_t *slots[] = {&out->manifest, &out->wasm, &out->signature};
    size_t off = 8;

    memset(out, 0, sizeof(*out));
    if (len < off || memcmp(buf, "ECAP", 4) != 0 || buf[4] < 1 || buf[4] > CAP_WASM_PKG_FORMAT_MAX || buf[5] != 3 ||
            buf[6] || buf[7]) {
        snprintf(err, err_size, "not an .ecapp package (format 1 or %d)", CAP_WASM_PKG_FORMAT_MAX);
        return false;
    }
    out->format = buf[4];
    for (int e = 0; e < 3; e++) {
        size_t name_len = off < len ? buf[off] : 0;
        size_t i;
        uint32_t data_len;

        if (name_len == 0 || off + 1 + name_len + 4 > len) {
            snprintf(err, err_size, "truncated package");
            return false;
        }
        for (i = 0; i < 3 && (strlen(names[i].name) != name_len ||
                              memcmp(names[i].name, buf + off + 1, name_len) != 0); i++) {
        }
        if (i == 3 || slots[i]->data) {
            snprintf(err, err_size, "unexpected or repeated entry '%.*s'", (int)name_len, (const char *)buf + off + 1);
            return false;
        }
        off += 1 + name_len;
        data_len = (uint32_t)buf[off] | (uint32_t)buf[off + 1] << 8 | (uint32_t)buf[off + 2] << 16 |
                   (uint32_t)buf[off + 3] << 24;
        off += 4;
        if (data_len == 0 || data_len > names[i].max || data_len > len - off) {
            snprintf(err, err_size, "%s is empty, truncated or larger than %u bytes", names[i].name,
                     (unsigned)names[i].max);
            return false;
        }
        slots[i]->data = buf + off;
        slots[i]->len = data_len;
        off += data_len;
    }
    if (off != len) {
        snprintf(err, err_size, "trailing data after the last entry");
        return false;
    }
    return true;
}

size_t cap_wasm_sig_canonical(const char *name, const char *version, const char *manifest_sha256,
                              const char *wasm_sha256, char *out, size_t size)
{
    int n = snprintf(out, size, "{\"name\":\"%s\",\"version\":\"%s\",\"manifest_sha256\":\"%s\",\"wasm_sha256\":\"%s\"}",
                     name, version, manifest_sha256, wasm_sha256);

    return n > 0 && (size_t)n < size ? (size_t)n : 0;
}

size_t cap_wasm_sig_record(uint16_t api, const char *name, const char *version,
                           const uint8_t manifest_sha[CAP_WASM_SHA_LEN], const uint8_t wasm_sha[CAP_WASM_SHA_LEN],
                           uint8_t *out, size_t size)
{
    size_t name_len = strlen(name);
    size_t version_len = strlen(version);
    size_t len = sizeof(CAP_WASM_SIG_V2_PREFIX) + 1 + 2 + 1 + name_len + 1 + version_len + 2 * CAP_WASM_SHA_LEN;
    uint8_t *p = out;

    if (name_len == 0 || name_len > CAP_WASM_APP_NAME_MAX || version_len == 0 || version_len > CAP_WASM_VERSION_MAX ||
            len > size) {
        return 0;
    }
    memcpy(p, CAP_WASM_SIG_V2_PREFIX, sizeof(CAP_WASM_SIG_V2_PREFIX)); /* including the NUL */
    p += sizeof(CAP_WASM_SIG_V2_PREFIX);
    *p++ = 2;
    *p++ = (uint8_t)(api & 0xff);
    *p++ = (uint8_t)(api >> 8);
    *p++ = (uint8_t)name_len;
    memcpy(p, name, name_len);
    p += name_len;
    *p++ = (uint8_t)version_len;
    memcpy(p, version, version_len);
    p += version_len;
    memcpy(p, manifest_sha, CAP_WASM_SHA_LEN);
    memcpy(p + CAP_WASM_SHA_LEN, wasm_sha, CAP_WASM_SHA_LEN);
    return len;
}

void cap_wasm_sha256(const uint8_t *data, size_t len, uint8_t out[CAP_WASM_SHA_LEN])
{
    mbedtls_sha256(data, len, out, 0);
}

void cap_wasm_sha256_hex(const uint8_t *data, size_t len, char out[CAP_WASM_SHA_HEX_LEN + 1])
{
    uint8_t hash[CAP_WASM_SHA_LEN];

    cap_wasm_sha256(data, len, hash);
    for (size_t i = 0; i < sizeof(hash); i++) {
        snprintf(out + 2 * i, 3, "%02x", hash[i]);
    }
}

/* Standard base64 into exactly `size` bytes. */
static bool cap_wasm_b64_decode(const char *b64, uint8_t *out, size_t size)
{
    uint8_t buf[72];
    size_t len = 0;

    if (!b64 || mbedtls_base64_decode(buf, sizeof(buf), &len, (const uint8_t *)b64, strlen(b64)) != 0 ||
            len != size) {
        return false;
    }
    memcpy(out, buf, size);
    return true;
}

bool cap_wasm_key_parse(const char *b64, cap_wasm_key_t *out)
{
    char hex[CAP_WASM_SHA_HEX_LEN + 1];

    if (!cap_wasm_b64_decode(b64, out->pub, sizeof(out->pub))) {
        return false;
    }
    cap_wasm_sha256_hex(out->pub, sizeof(out->pub), hex);
    memcpy(out->key_id, hex, CAP_WASM_KEY_ID_LEN);
    out->key_id[CAP_WASM_KEY_ID_LEN] = '\0';
    return true;
}

static const char *cap_wasm_json_str(const cJSON *obj, const char *key)
{
    return cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(obj, key));
}

/*
 * Format 1: the "signed" object must repeat the manifest's name and version and the hex hashes of
 * the entries; the signature is over its canonical JSON. Returns the signed bytes in `msg`.
 */
static bool cap_wasm_sig_v1_message(const cJSON *root, const cap_wasm_manifest_t *mf,
                                    const uint8_t *manifest, size_t manifest_len, const uint8_t *wasm, size_t wasm_len,
                                    uint8_t *msg, size_t msg_size, size_t *msg_len, char *err, size_t err_size)
{
    static const char *const keys_signed[] = {"name", "version", "manifest_sha256", "wasm_sha256"};
    const cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(root, "signed");
    const char *s_name = cap_wasm_json_str(sig_obj, "name");
    const char *s_version = cap_wasm_json_str(sig_obj, "version");
    const char *s_manifest = cap_wasm_json_str(sig_obj, "manifest_sha256");
    const char *s_wasm = cap_wasm_json_str(sig_obj, "wasm_sha256");
    char manifest_hex[CAP_WASM_SHA_HEX_LEN + 1];
    char wasm_hex[CAP_WASM_SHA_HEX_LEN + 1];

    if (!cJSON_IsObject(sig_obj)) {
        snprintf(err, err_size, "signature.json is not a signature object");
        return false;
    }
    if (!cap_wasm_keys_known(sig_obj, keys_signed, 4, "signed key", err, err_size)) {
        return false;
    }
    if (!s_name || !s_version || !s_manifest || !s_wasm) {
        snprintf(err, err_size, "signature.json needs alg \"ed25519\", key_id, sig and all signed fields");
        return false;
    }
    if (strcmp(s_name, mf->name) != 0 || strcmp(s_version, mf->version) != 0) {
        snprintf(err, err_size, "signed name/version do not match manifest.json");
        return false;
    }
    cap_wasm_sha256_hex(manifest, manifest_len, manifest_hex);
    cap_wasm_sha256_hex(wasm, wasm_len, wasm_hex);
    if (strcmp(s_manifest, manifest_hex) != 0 || strcmp(s_wasm, wasm_hex) != 0) {
        snprintf(err, err_size, "%s does not match its signed hash",
                 strcmp(s_manifest, manifest_hex) != 0 ? "manifest.json" : "app.wasm");
        return false;
    }
    *msg_len = cap_wasm_sig_canonical(s_name, s_version, s_manifest, s_wasm, (char *)msg, msg_size);
    return *msg_len != 0;
}

/* Format 2: the signed record is built from the manifest and the entry bytes; nothing is repeated. */
static bool cap_wasm_sig_v2_message(const cap_wasm_manifest_t *mf, const uint8_t *manifest, size_t manifest_len,
                                    const uint8_t *wasm, size_t wasm_len, uint8_t *msg, size_t msg_size,
                                    size_t *msg_len, char *err, size_t err_size)
{
    uint8_t manifest_sha[CAP_WASM_SHA_LEN];
    uint8_t wasm_sha[CAP_WASM_SHA_LEN];

    if (!mf->has_api) {
        snprintf(err, err_size, "a format 2 package needs \"api\" in manifest.json");
        return false;
    }
    cap_wasm_sha256(manifest, manifest_len, manifest_sha);
    cap_wasm_sha256(wasm, wasm_len, wasm_sha);
    *msg_len = cap_wasm_sig_record(mf->api, mf->name, mf->version, manifest_sha, wasm_sha, msg, msg_size);
    return *msg_len != 0;
}

bool cap_wasm_sig_verify(const char *sig_json, const cap_wasm_manifest_t *mf,
                         const uint8_t *manifest, size_t manifest_len, const uint8_t *wasm, size_t wasm_len,
                         const cap_wasm_key_t *keys, size_t key_count, int expect_format,
                         char key_id[CAP_WASM_KEY_ID_LEN + 1], char *err, size_t err_size)
{
    static const char *const keys_v1[] = {"alg", "key_id", "sdk", "signed", "sig"};
    static const char *const keys_v2[] = {"alg", "key_id", "sdk", "sig"};
    cJSON *root = cJSON_Parse(sig_json);
    const cJSON *sdk = cJSON_GetObjectItemCaseSensitive(root, "sdk");
    const char *alg = cap_wasm_json_str(root, "alg");
    const char *kid = cap_wasm_json_str(root, "key_id");
    const char *sig_b64 = cap_wasm_json_str(root, "sig");
    uint8_t msg[320]; /* a format 1 canonical object, or a format 2 record */
    uint8_t sig[64];
    size_t msg_len = 0;
    size_t k;
    int format;
    bool ok = false;

    if (!cJSON_IsObject(root)) {
        snprintf(err, err_size, "signature.json is not a signature object");
        goto done;
    }
    if (!cJSON_IsNumber(sdk) || sdk->valuedouble < 1 || sdk->valuedouble > CAP_WASM_PKG_FORMAT_MAX ||
            sdk->valuedouble != (double)(int)sdk->valuedouble) {
        snprintf(err, err_size, "unsupported sdk version (device supports 1-%d)", CAP_WASM_PKG_FORMAT_MAX);
        goto done;
    }
    format = (int)sdk->valuedouble;
    if (expect_format && format != expect_format) {
        snprintf(err, err_size, "signature format %d in a format %d package", format, expect_format);
        goto done;
    }
    if (!cap_wasm_keys_known(root, format == 1 ? keys_v1 : keys_v2, format == 1 ? 5 : 4, "signature key", err,
                             err_size)) {
        goto done;
    }
    if (!alg || strcmp(alg, "ed25519") != 0 || !kid || !sig_b64) {
        snprintf(err, err_size, "signature.json needs alg \"ed25519\", key_id, sig and all signed fields");
        goto done;
    }
    if (format == 1 ? !cap_wasm_sig_v1_message(root, mf, manifest, manifest_len, wasm, wasm_len, msg, sizeof(msg),
                                                &msg_len, err, err_size) :
            !cap_wasm_sig_v2_message(mf, manifest, manifest_len, wasm, wasm_len, msg, sizeof(msg), &msg_len, err,
                                     err_size)) {
        goto done;
    }
    for (k = 0; k < key_count && strcmp(keys[k].key_id, kid) != 0; k++) {
    }
    if (k == key_count) {
        snprintf(err, err_size, "signed by untrusted key %.8s", kid);
        goto done;
    }
    if (!cap_wasm_b64_decode(sig_b64, sig, sizeof(sig)) || crypto_ed25519_check(sig, keys[k].pub, msg, msg_len) != 0) {
        snprintf(err, err_size, "invalid signature (key %s)", keys[k].key_id);
        goto done;
    }
    strcpy(key_id, keys[k].key_id);
    ok = true;

done:
    cJSON_Delete(root);
    return ok;
}

bool cap_wasm_api_check(const cap_wasm_manifest_t *mf, char *err, size_t err_size)
{
    if (mf->api > CAP_WASM_API_VERSION) {
        snprintf(err, err_size, "needs claw api %u, firmware has %u", (unsigned)mf->api, CAP_WASM_API_VERSION);
        return false;
    }
    return true;
}

size_t cap_wasm_fw_sig_canonical(const char *project, const char *version, uint32_t size, const char *sha256,
                                 char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "{\"project\":\"%s\",\"version\":\"%s\",\"size\":%" PRIu32 ",\"sha256\":\"%s\"}",
                     project, version, size, sha256);

    return n > 0 && (size_t)n < out_size ? (size_t)n : 0;
}

/* 1..max printable ASCII chars that JSON would not escape. */
static bool cap_wasm_fw_text_ok(const char *s, size_t max)
{
    size_t len = s ? strlen(s) : 0;

    if (len == 0 || len > max) {
        return false;
    }
    for (; *s; s++) {
        if (*s < 0x20 || *s > 0x7e || *s == '"' || *s == '\\') {
            return false;
        }
    }
    return true;
}

bool cap_wasm_fw_sig_verify(const char *sig_json, const cap_wasm_key_t *keys, size_t key_count,
                            cap_wasm_fw_sig_t *out, char *err, size_t err_size)
{
    static const char *const keys_top[] = {"alg", "key_id", "version", "project", "size", "sha256", "sig"};
    cJSON *root = cJSON_Parse(sig_json);
    const cJSON *size = cJSON_GetObjectItemCaseSensitive(root, "size");
    const char *alg = cap_wasm_json_str(root, "alg");
    const char *kid = cap_wasm_json_str(root, "key_id");
    const char *version = cap_wasm_json_str(root, "version");
    const char *project = cap_wasm_json_str(root, "project");
    const char *sha256 = cap_wasm_json_str(root, "sha256");
    const char *sig_b64 = cap_wasm_json_str(root, "sig");
    char canonical[192];
    uint8_t sig[64];
    size_t canonical_len;
    size_t k;
    bool ok = false;

    memset(out, 0, sizeof(*out));
    if (!cJSON_IsObject(root)) {
        snprintf(err, err_size, "the .sig.json is not a signature object");
        goto done;
    }
    if (!cap_wasm_keys_known(root, keys_top, 7, "signature key", err, err_size)) {
        goto done;
    }
    if (!alg || strcmp(alg, "ed25519") != 0 || !kid || !sig_b64 || !cap_wasm_fw_text_ok(version, CAP_WASM_FW_TEXT_MAX) ||
            !cap_wasm_fw_text_ok(project, CAP_WASM_FW_TEXT_MAX) || !sha256 || strlen(sha256) != CAP_WASM_SHA_HEX_LEN ||
            strspn(sha256, "0123456789abcdef") != CAP_WASM_SHA_HEX_LEN || !cJSON_IsNumber(size) ||
            size->valuedouble < 1 || size->valuedouble > UINT32_MAX || size->valuedouble != (double)(uint32_t)size->valuedouble) {
        snprintf(err, err_size, "the .sig.json needs alg \"ed25519\", key_id, version, project, size, sha256 and sig");
        goto done;
    }
    for (k = 0; k < key_count && strcmp(keys[k].key_id, kid) != 0; k++) {
    }
    if (k == key_count) {
        snprintf(err, err_size, "signed by untrusted key %.8s", kid);
        goto done;
    }
    out->size = (uint32_t)size->valuedouble;
    canonical_len = cap_wasm_fw_sig_canonical(project, version, out->size, sha256, canonical, sizeof(canonical));
    if (!cap_wasm_b64_decode(sig_b64, sig, sizeof(sig)) || canonical_len == 0 ||
            crypto_ed25519_check(sig, keys[k].pub, (const uint8_t *)canonical, canonical_len) != 0) {
        snprintf(err, err_size, "invalid signature (key %s)", keys[k].key_id);
        goto done;
    }
    strcpy(out->project, project);
    strcpy(out->version, version);
    strcpy(out->sha256, sha256);
    strcpy(out->key_id, keys[k].key_id);
    ok = true;

done:
    cJSON_Delete(root);
    return ok;
}

typedef struct {
    unsigned long num[3];
    const char *pre;     /* NULL for a release */
    size_t pre_len;
} cap_wasm_version_t;

static bool cap_wasm_version_parse(const char *s, cap_wasm_version_t *v)
{
    for (int i = 0; i < 3; i++) {
        char *end;

        if (*s < '0' || *s > '9') {
            return false;
        }
        v->num[i] = strtoul(s, &end, 10);
        s = end;
        if (i < 2 && *s++ != '.') {
            return false;
        }
    }
    v->pre = NULL;
    v->pre_len = 0;
    if (*s == '-') {
        v->pre = ++s;
        v->pre_len = strcspn(s, "+");
        s += v->pre_len;
        if (v->pre_len == 0) {
            return false;
        }
    }
    return *s == '\0' || (*s == '+' && s[1]);
}

/* Compares dot-separated pre-release identifiers. */
static int cap_wasm_pre_cmp(const char *a, size_t a_len, const char *b, size_t b_len)
{
    while (a_len && b_len) {
        size_t la = strcspn(a, ".+");
        size_t lb = strcspn(b, ".+");
        bool na = strspn(a, "0123456789") >= la;
        bool nb = strspn(b, "0123456789") >= lb;
        int c;

        la = la < a_len ? la : a_len;
        lb = lb < b_len ? lb : b_len;
        if (na != nb) {
            return na ? -1 : 1;
        }
        if (na && la != lb) {
            return la < lb ? -1 : 1;
        }
        c = memcmp(a, b, la < lb ? la : lb);
        if (c || la != lb) {
            return c ? c : la < lb ? -1 : 1;
        }
        a += la;
        b += lb;
        a_len -= la;
        b_len -= lb;
        if (a_len && *a == '.') {
            a++, a_len--;
        }
        if (b_len && *b == '.') {
            b++, b_len--;
        }
    }
    return a_len ? 1 : b_len ? -1 : 0;
}

bool cap_wasm_version_cmp(const char *a, const char *b, int *out)
{
    cap_wasm_version_t va;
    cap_wasm_version_t vb;

    if (!cap_wasm_version_parse(a, &va) || !cap_wasm_version_parse(b, &vb)) {
        return false;
    }
    for (int i = 0; i < 3; i++) {
        if (va.num[i] != vb.num[i]) {
            *out = va.num[i] < vb.num[i] ? -1 : 1;
            return true;
        }
    }
    if (!va.pre || !vb.pre) {
        *out = va.pre ? -1 : vb.pre ? 1 : 0;
    } else {
        *out = cap_wasm_pre_cmp(va.pre, va.pre_len, vb.pre, vb.pre_len);
    }
    return true;
}

size_t cap_wasm_index_record(const uint8_t index_sha[CAP_WASM_SHA_LEN], uint64_t expires, uint8_t *out, size_t size)
{
    uint8_t *p = out;

    if (size < CAP_WASM_INDEX_RECORD_LEN) {
        return 0;
    }
    memcpy(p, CAP_WASM_INDEX_PREFIX, sizeof(CAP_WASM_INDEX_PREFIX)); /* including the NUL */
    p += sizeof(CAP_WASM_INDEX_PREFIX);
    memcpy(p, index_sha, CAP_WASM_SHA_LEN);
    p += CAP_WASM_SHA_LEN;
    for (int i = 0; i < 8; i++) {
        *p++ = (uint8_t)(expires >> (8 * i));
    }
    return CAP_WASM_INDEX_RECORD_LEN;
}

/* A non-negative integer that survives the double; unix times and sizes. */
static bool cap_wasm_json_int64(const cJSON *item, int64_t *out)
{
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > 9007199254740992.0 ||
            item->valuedouble != (double)(int64_t)item->valuedouble) {
        return false;
    }
    *out = (int64_t)item->valuedouble;
    return true;
}

static bool cap_wasm_index_entry_parse(const cJSON *item, cap_wasm_index_entry_t *out)
{
    static const char *const keys[] = {"name", "version", "url", "sha256", "size"};
    const char *name = cap_wasm_json_str(item, "name");
    const char *version = cap_wasm_json_str(item, "version");
    const char *url = cap_wasm_json_str(item, "url");
    const char *sha256 = cap_wasm_json_str(item, "sha256");
    char unused[8];
    int64_t size = 0;
    int cmp;

    if (!cJSON_IsObject(item) || !cap_wasm_keys_known(item, keys, 5, "index entry key", unused, sizeof(unused)) ||
            !name || !cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX) || !version ||
            strlen(version) > CAP_WASM_VERSION_MAX || !cap_wasm_version_cmp(version, version, &cmp) || !url ||
            strncmp(url, "https://", 8) != 0 || strlen(url) >= CAP_WASM_INDEX_URL_MAX || !sha256 ||
            strlen(sha256) != CAP_WASM_SHA_HEX_LEN || strspn(sha256, "0123456789abcdef") != CAP_WASM_SHA_HEX_LEN ||
            !cap_wasm_json_int64(cJSON_GetObjectItemCaseSensitive(item, "size"), &size) || size < 1 ||
            size > CAP_WASM_PKG_MAX) {
        return false;
    }
    strcpy(out->name, name);
    strcpy(out->version, version);
    strcpy(out->url, url);
    strcpy(out->sha256, sha256);
    out->size = (uint32_t)size;
    return true;
}

bool cap_wasm_index_check(const char *index, size_t index_len, const char *sig_json,
                          const cap_wasm_key_t *keys, size_t key_count, int64_t now, bool clock_synced,
                          int64_t last_issued, const char *name, cap_wasm_index_t *out,
                          cap_wasm_index_entry_t *entry, char *err, size_t err_size)
{
    static const char *const keys_sig[] = {"alg", "key_id", "expires", "sig"};
    static const char *const keys_index[] = {"format", "issued", "expires", "apps"};
    cJSON *sig_root = cJSON_Parse(sig_json);
    cJSON *root = NULL;
    const cJSON *apps = NULL;
    const cJSON *item = NULL;
    const char *alg = cap_wasm_json_str(sig_root, "alg");
    const char *kid = cap_wasm_json_str(sig_root, "key_id");
    const char *sig_b64 = cap_wasm_json_str(sig_root, "sig");
    uint8_t index_sha[CAP_WASM_SHA_LEN];
    uint8_t record[CAP_WASM_INDEX_RECORD_LEN];
    uint8_t sig[64];
    int64_t sig_expires = 0;
    int64_t format = 0;
    size_t k;
    bool found = false;
    bool ok = false;

    memset(out, 0, sizeof(*out));
    if (!cJSON_IsObject(sig_root)) {
        snprintf(err, err_size, "index.sig is not a signature object");
        goto done;
    }
    if (!cap_wasm_keys_known(sig_root, keys_sig, 4, "index.sig key", err, err_size)) {
        goto done;
    }
    if (!alg || strcmp(alg, "ed25519") != 0 || !kid || !sig_b64 ||
            !cap_wasm_json_int64(cJSON_GetObjectItemCaseSensitive(sig_root, "expires"), &sig_expires)) {
        snprintf(err, err_size, "index.sig needs alg \"ed25519\", key_id, expires and sig");
        goto done;
    }
    for (k = 0; k < key_count && strcmp(keys[k].key_id, kid) != 0; k++) {
    }
    if (k == key_count) {
        snprintf(err, err_size, "index signed by untrusted key %.8s", kid);
        goto done;
    }
    /* The signature covers the bytes as served, so it is checked before they are parsed. */
    cap_wasm_sha256((const uint8_t *)index, index_len, index_sha);
    cap_wasm_index_record(index_sha, (uint64_t)sig_expires, record, sizeof(record));
    if (!cap_wasm_b64_decode(sig_b64, sig, sizeof(sig)) ||
            crypto_ed25519_check(sig, keys[k].pub, record, sizeof(record)) != 0) {
        snprintf(err, err_size, "invalid index signature (key %s)", keys[k].key_id);
        goto done;
    }
    root = cJSON_ParseWithLength(index, index_len);
    if (!cJSON_IsObject(root)) {
        snprintf(err, err_size, "index.json is not a JSON object");
        goto done;
    }
    if (!cap_wasm_keys_known(root, keys_index, 4, "index key", err, err_size)) {
        goto done;
    }
    if (!cap_wasm_json_int64(cJSON_GetObjectItemCaseSensitive(root, "format"), &format) || format != CAP_WASM_INDEX_FORMAT) {
        snprintf(err, err_size, "unsupported index format (device supports %d)", CAP_WASM_INDEX_FORMAT);
        goto done;
    }
    if (!cap_wasm_json_int64(cJSON_GetObjectItemCaseSensitive(root, "issued"), &out->issued) ||
            !cap_wasm_json_int64(cJSON_GetObjectItemCaseSensitive(root, "expires"), &out->expires) ||
            out->issued > out->expires) {
        snprintf(err, err_size, "index.json needs integer issued and expires times, issued first");
        goto done;
    }
    if (out->expires != sig_expires) {
        snprintf(err, err_size, "index.json expires (%lld) does not match the signed expires (%lld)",
                 (long long)out->expires, (long long)sig_expires);
        goto done;
    }
    if (!clock_synced) {
        snprintf(err, err_size, "clock not synced, cannot verify index freshness");
        goto done;
    }
    if (now > out->expires) {
        snprintf(err, err_size, "index expired at %lld (now %lld); the publisher must sign a new one",
                 (long long)out->expires, (long long)now);
        goto done;
    }
    if (out->issued < last_issued) {
        snprintf(err, err_size, "index issued %lld is older than the last accepted index (%lld): stale or replayed",
                 (long long)out->issued, (long long)last_issued);
        goto done;
    }
    strcpy(out->key_id, keys[k].key_id);
    apps = cJSON_GetObjectItemCaseSensitive(root, "apps");
    if (!cJSON_IsArray(apps)) {
        snprintf(err, err_size, "index.json apps must be an array");
        goto done;
    }
    if (!name) {
        ok = true;
        goto done;
    }
    cJSON_ArrayForEach(item, apps) {
        const char *item_name = cap_wasm_json_str(item, "name");

        if (item_name && strcmp(item_name, name) == 0) {
            if (!cap_wasm_index_entry_parse(item, entry)) {
                snprintf(err, err_size, "the index entry for %s is invalid", name);
                goto done;
            }
            found = true;
            break;
        }
    }
    if (!found) {
        snprintf(err, err_size, "no entry for app %s in the index", name);
        goto done;
    }
    ok = true;

done:
    cJSON_Delete(sig_root);
    cJSON_Delete(root);
    return ok;
}

bool cap_wasm_index_url(const char *source_url, char *out, size_t size)
{
    static const char gh[] = "https://github.com/";
    static const char dl[] = "/releases/download/";
    const char *path = strncmp(source_url, "https://", 8) == 0 ? strchr(source_url + 8, '/') : NULL;
    const char *rel = strncmp(source_url, gh, sizeof(gh) - 1) == 0 ? strstr(source_url + sizeof(gh) - 1, dl) : NULL;
    const char *dir;
    int n;

    if (!path || strpbrk(source_url, "?#")) {
        return false;
    }
    if (rel) {
        n = snprintf(out, size, "%.*s/releases/latest/download/%s", (int)(rel - source_url), source_url,
                     CAP_WASM_INDEX_FILE);
    } else {
        dir = strrchr(path, '/');
        n = snprintf(out, size, "%.*s/%s", (int)(dir - source_url), source_url, CAP_WASM_INDEX_FILE);
    }
    return n > 0 && (size_t)n < size;
}

bool cap_wasm_rollback_check(const char *name, const char *version, const char *floor, bool allow_downgrade,
                             char *err, size_t err_size)
{
    int cmp = 0;

    if (!floor[0] || allow_downgrade) {
        return true;
    }
    if (!cap_wasm_version_cmp(version, floor, &cmp)) {
        snprintf(err, err_size, "cannot compare %s %s with the version floor %s; /app install %s <url> installs it anyway",
                 name, version, floor, CAP_WASM_DOWNGRADE_FLAG);
        return false;
    }
    if (cmp < 0) {
        snprintf(err, err_size, "%s %s is below the version floor %s (anti-rollback); /app install %s <url> installs "
                 "it anyway", name, version, floor, CAP_WASM_DOWNGRADE_FLAG);
        return false;
    }
    return true;
}

int cap_wasm_lru_pick(const int64_t *last_used, const bool *loaded, size_t count, int skip)
{
    int pick = -1;

    for (size_t i = 0; i < count; i++) {
        if (loaded[i] && (int)i != skip && (pick < 0 || last_used[i] < last_used[pick])) {
            pick = (int)i;
        }
    }
    return pick;
}
