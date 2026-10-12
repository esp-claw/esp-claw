/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/*
 * Signed app packages (.ecapp), signature checks, version order and eviction choice. Pure C +
 * cJSON + mbedTLS (SHA-256, base64) + Monocypher (Ed25519) so it can be unit-tested on the host.
 * tools/ecapp.py of github.com/esp-claw/app-sdk is the host side.
 *
 * Package: "ECAP", u8 format (1 or 2), u8 entry count (3), u16 reserved (0), then per entry
 * u8 name length, name, u32 little-endian data length, data. The entries are exactly
 * manifest.json, app.wasm and signature.json, in any order, with nothing after the last one.
 *
 * signature.json, format 1 (still accepted):
 *   {"alg":"ed25519","key_id":"<8 hex>","sdk":1,"signed":{...},"sig":"<base64>"}
 * "sig" is the Ed25519 signature over the canonical bytes of "signed":
 *   {"name":"<name>","version":"<version>","manifest_sha256":"<hex>","wasm_sha256":"<hex>"}
 * in exactly this key order, no whitespace, lowercase hex (64 chars). Names and versions cannot
 * contain characters JSON would escape. key_id is the first 8 hex chars of sha256(public key).
 *
 * signature.json, format 2: {"alg":"ed25519","key_id":"<8 hex>","sdk":2,"sig":"<base64>"}.
 * There is no "signed" object: "sig" is the Ed25519 signature over this binary record, built by
 * the verifier from the manifest and the entry bytes (cap_wasm_sig_record()):
 *
 *   offset  size  value
 *   0       13    "ecapp-sig-v2" followed by one NUL byte (domain separation)
 *   13      1     u8 format = 2
 *   14      2     u16 little-endian api (manifest "api", the claw import module version)
 *   16      1     u8 name length N (1..24)
 *   17      N     name, as in the manifest (no NUL)
 *   17+N    1     u8 version length V (1..16)
 *   18+N    V     version, as in the manifest (no NUL)
 *   18+N+V  32    SHA-256 of the manifest.json bytes
 *   50+N+V  32    SHA-256 of the app.wasm bytes
 *
 * At most 122 bytes. Format 2 packages must declare "api" in the manifest. The package format
 * byte and the signature's "sdk" value are the same number (1 or 2) and must agree.
 * test/host/ecapp_vectors.json holds a test key, a record and its signature; the SDK ships the
 * same file.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cap_wasm_manifest.h"

#define CAP_WASM_PKG_MAX         (512 * 1024)
#define CAP_WASM_WASM_MAX        (256 * 1024)
#define CAP_WASM_MANIFEST_MAX    4096
#define CAP_WASM_SIGNATURE_MAX   1024
#define CAP_WASM_PKG_FORMAT_MAX  2    /* highest signature.json "sdk" / package format accepted */
#define CAP_WASM_API_VERSION     1    /* claw import module version this firmware implements */
#define CAP_WASM_KEY_ID_LEN      8
#define CAP_WASM_SHA_LEN         32
#define CAP_WASM_SHA_HEX_LEN     64
#define CAP_WASM_MAX_TRUSTED     8
#define CAP_WASM_SIG_V2_PREFIX   "ecapp-sig-v2"
#define CAP_WASM_SIG_V2_MAX      (sizeof(CAP_WASM_SIG_V2_PREFIX) + 1 + 2 + 1 + CAP_WASM_APP_NAME_MAX + 1 + \
                                  CAP_WASM_VERSION_MAX + 2 * CAP_WASM_SHA_LEN)

typedef struct {
    const uint8_t *data;
    size_t len;
} cap_wasm_blob_t;

typedef struct {
    cap_wasm_blob_t manifest;
    cap_wasm_blob_t wasm;
    cap_wasm_blob_t signature;
    uint8_t format;
} cap_wasm_pkg_t;

typedef struct {
    uint8_t pub[32];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
} cap_wasm_key_t;

/* Splits a package into its entries (pointing into `buf`). */
bool cap_wasm_pkg_parse(const uint8_t *buf, size_t len, cap_wasm_pkg_t *out, char *err, size_t err_size);

/* Writes the canonical signed bytes of a format 1 signature; returns their length, or 0 when `size` is too small. */
size_t cap_wasm_sig_canonical(const char *name, const char *version, const char *manifest_sha256,
                              const char *wasm_sha256, char *out, size_t size);

/* Writes the format 2 signature record (see above); returns its length, or 0 when `size` is too small. */
size_t cap_wasm_sig_record(uint16_t api, const char *name, const char *version,
                           const uint8_t manifest_sha[CAP_WASM_SHA_LEN], const uint8_t wasm_sha[CAP_WASM_SHA_LEN],
                           uint8_t *out, size_t size);

/* SHA-256 of `data`, raw and as lowercase hex. */
void cap_wasm_sha256(const uint8_t *data, size_t len, uint8_t out[CAP_WASM_SHA_LEN]);
void cap_wasm_sha256_hex(const uint8_t *data, size_t len, char out[CAP_WASM_SHA_HEX_LEN + 1]);

/* Decodes a base64 raw 32-byte Ed25519 public key and derives its key_id. */
bool cap_wasm_key_parse(const char *b64, cap_wasm_key_t *out);

/*
 * Checks signature.json for the app `mf` describes: the format, name, version and (format 2) api
 * against the manifest, both hashes against the bytes, key_id against `keys` and the Ed25519
 * signature. `expect_format` is the package format byte, or 0 when the files come from the app
 * directory. On success `key_id` is the signing key's id.
 */
bool cap_wasm_sig_verify(const char *sig_json, const cap_wasm_manifest_t *mf,
                         const uint8_t *manifest, size_t manifest_len, const uint8_t *wasm, size_t wasm_len,
                         const cap_wasm_key_t *keys, size_t key_count, int expect_format,
                         char key_id[CAP_WASM_KEY_ID_LEN + 1], char *err, size_t err_size);

/* False with `err` ("needs claw api N, firmware has M") when the manifest's api is above CAP_WASM_API_VERSION. */
bool cap_wasm_api_check(const cap_wasm_manifest_t *mf, char *err, size_t err_size);

/*
 * Firmware signature (<image>.sig.json, written by tools/fwsign.py):
 *   {"alg":"ed25519","key_id":"<8 hex>","version":"<v>","project":"<p>","size":N,"sha256":"<hex>","sig":"<b64>"}
 * "sig" is the Ed25519 signature over the canonical bytes
 *   {"project":"<p>","version":"<v>","size":N,"sha256":"<hex>"}
 * in exactly this key order, no whitespace, lowercase hex. project and version are the image's
 * esp_app_desc_t fields: 1-31 printable ASCII chars without '"' or '\\'.
 */
#define CAP_WASM_FW_TEXT_MAX 31

typedef struct {
    char project[CAP_WASM_FW_TEXT_MAX + 1];
    char version[CAP_WASM_FW_TEXT_MAX + 1];
    uint32_t size;
    char sha256[CAP_WASM_SHA_HEX_LEN + 1];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
} cap_wasm_fw_sig_t;

/* Writes the canonical signed bytes of a firmware signature; returns their length, or 0 when too small. */
size_t cap_wasm_fw_sig_canonical(const char *project, const char *version, uint32_t size, const char *sha256,
                                 char *out, size_t out_size);

/*
 * Parses a firmware signature, checks its format, that key_id is in `keys` and the Ed25519
 * signature. The image itself is checked later against out->size and out->sha256.
 */
bool cap_wasm_fw_sig_verify(const char *sig_json, const cap_wasm_key_t *keys, size_t key_count,
                            cap_wasm_fw_sig_t *out, char *err, size_t err_size);

/*
 * Orders MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD] versions like semver: numeric fields, a
 * pre-release sorts before its release, pre-release identifiers compare numerically when both are
 * digits and as ASCII otherwise (digits first), build metadata is ignored. Returns false when
 * either version does not have that form; otherwise *out is <0, 0 or >0.
 */
bool cap_wasm_version_cmp(const char *a, const char *b, int *out);

/* Index of the least recently used loaded entry other than `skip`, or -1. */
int cap_wasm_lru_pick(const int64_t *last_used, const bool *loaded, size_t count, int skip);
