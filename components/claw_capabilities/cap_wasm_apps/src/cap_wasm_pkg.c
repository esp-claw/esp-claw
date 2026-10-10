/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_pkg.h"

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
    if (len < off || memcmp(buf, "ECAP", 4) != 0 || buf[4] != 1 || buf[5] != 3 || buf[6] || buf[7]) {
        snprintf(err, err_size, "not an .ecapp package (format 1)");
        return false;
    }
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

void cap_wasm_sha256_hex(const uint8_t *data, size_t len, char out[CAP_WASM_SHA_HEX_LEN + 1])
{
    uint8_t hash[32];

    mbedtls_sha256(data, len, hash, 0);
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

bool cap_wasm_sig_verify(const char *sig_json, const cap_wasm_manifest_t *mf,
                         const uint8_t *manifest, size_t manifest_len, const uint8_t *wasm, size_t wasm_len,
                         const cap_wasm_key_t *keys, size_t key_count,
                         char key_id[CAP_WASM_KEY_ID_LEN + 1], char *err, size_t err_size)
{
    static const char *const keys_top[] = {"alg", "key_id", "sdk", "signed", "sig"};
    static const char *const keys_signed[] = {"name", "version", "manifest_sha256", "wasm_sha256"};
    cJSON *root = cJSON_Parse(sig_json);
    const cJSON *sdk = cJSON_GetObjectItemCaseSensitive(root, "sdk");
    const cJSON *sig_obj = cJSON_GetObjectItemCaseSensitive(root, "signed");
    const char *alg = cap_wasm_json_str(root, "alg");
    const char *kid = cap_wasm_json_str(root, "key_id");
    const char *sig_b64 = cap_wasm_json_str(root, "sig");
    const char *s_name = cap_wasm_json_str(sig_obj, "name");
    const char *s_version = cap_wasm_json_str(sig_obj, "version");
    const char *s_manifest = cap_wasm_json_str(sig_obj, "manifest_sha256");
    const char *s_wasm = cap_wasm_json_str(sig_obj, "wasm_sha256");
    char manifest_hex[CAP_WASM_SHA_HEX_LEN + 1];
    char wasm_hex[CAP_WASM_SHA_HEX_LEN + 1];
    char canonical[320];
    uint8_t sig[64];
    size_t canonical_len;
    size_t k;
    bool ok = false;

    if (!cJSON_IsObject(root) || !cJSON_IsObject(sig_obj)) {
        snprintf(err, err_size, "signature.json is not a signature object");
        goto done;
    }
    if (!cap_wasm_keys_known(root, keys_top, 5, "signature key", err, err_size) ||
            !cap_wasm_keys_known(sig_obj, keys_signed, 4, "signed key", err, err_size)) {
        goto done;
    }
    if (!alg || strcmp(alg, "ed25519") != 0 || !kid || !sig_b64 || !s_name || !s_version || !s_manifest || !s_wasm) {
        snprintf(err, err_size, "signature.json needs alg \"ed25519\", key_id, sig and all signed fields");
        goto done;
    }
    if (!cJSON_IsNumber(sdk) || sdk->valuedouble != CAP_WASM_SDK_VERSION) {
        snprintf(err, err_size, "unsupported sdk version (device supports %d)", CAP_WASM_SDK_VERSION);
        goto done;
    }
    if (strcmp(s_name, mf->name) != 0 || strcmp(s_version, mf->version) != 0) {
        snprintf(err, err_size, "signed name/version do not match manifest.json");
        goto done;
    }
    cap_wasm_sha256_hex(manifest, manifest_len, manifest_hex);
    cap_wasm_sha256_hex(wasm, wasm_len, wasm_hex);
    if (strcmp(s_manifest, manifest_hex) != 0 || strcmp(s_wasm, wasm_hex) != 0) {
        snprintf(err, err_size, "%s does not match its signed hash",
                 strcmp(s_manifest, manifest_hex) != 0 ? "manifest.json" : "app.wasm");
        goto done;
    }
    for (k = 0; k < key_count && strcmp(keys[k].key_id, kid) != 0; k++) {
    }
    if (k == key_count) {
        snprintf(err, err_size, "signed by untrusted key %.8s", kid);
        goto done;
    }
    canonical_len = cap_wasm_sig_canonical(s_name, s_version, s_manifest, s_wasm, canonical, sizeof(canonical));
    if (!cap_wasm_b64_decode(sig_b64, sig, sizeof(sig)) || canonical_len == 0 ||
            crypto_ed25519_check(sig, keys[k].pub, (const uint8_t *)canonical, canonical_len) != 0) {
        snprintf(err, err_size, "invalid signature (key %s)", keys[k].key_id);
        goto done;
    }
    strcpy(key_id, keys[k].key_id);
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
