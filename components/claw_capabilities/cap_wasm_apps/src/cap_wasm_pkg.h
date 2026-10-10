/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

/*
 * Signed app packages (.ecapp), signature checks, version order and eviction choice. Pure C +
 * cJSON + mbedTLS (SHA-256, base64) + Monocypher (Ed25519) so it can be unit-tested on the host.
 * apps/sdk/tools/ecapp.py is the host side.
 *
 * Package: "ECAP", u8 format (1), u8 entry count (3), u16 reserved (0), then per entry
 * u8 name length, name, u32 little-endian data length, data. The entries are exactly
 * manifest.json, app.wasm and signature.json, in any order, with nothing after the last one.
 *
 * signature.json: {"alg":"ed25519","key_id":"<8 hex>","sdk":1,"signed":{...},"sig":"<base64>"}.
 * "sig" is the Ed25519 signature over the canonical bytes of "signed":
 *   {"name":"<name>","version":"<version>","manifest_sha256":"<hex>","wasm_sha256":"<hex>"}
 * in exactly this key order, no whitespace, lowercase hex (64 chars). Names and versions cannot
 * contain characters JSON would escape. key_id is the first 8 hex chars of sha256(public key).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cap_wasm_manifest.h"

#define CAP_WASM_PKG_MAX         (512 * 1024)
#define CAP_WASM_WASM_MAX        (256 * 1024)
#define CAP_WASM_MANIFEST_MAX    4096
#define CAP_WASM_SIGNATURE_MAX   1024
#define CAP_WASM_SDK_VERSION     1
#define CAP_WASM_KEY_ID_LEN      8
#define CAP_WASM_SHA_HEX_LEN     64
#define CAP_WASM_MAX_TRUSTED     8

typedef struct {
    const uint8_t *data;
    size_t len;
} cap_wasm_blob_t;

typedef struct {
    cap_wasm_blob_t manifest;
    cap_wasm_blob_t wasm;
    cap_wasm_blob_t signature;
} cap_wasm_pkg_t;

typedef struct {
    uint8_t pub[32];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
} cap_wasm_key_t;

/* Splits a package into its entries (pointing into `buf`). */
bool cap_wasm_pkg_parse(const uint8_t *buf, size_t len, cap_wasm_pkg_t *out, char *err, size_t err_size);

/* Writes the canonical signed bytes; returns their length, or 0 when `size` is too small. */
size_t cap_wasm_sig_canonical(const char *name, const char *version, const char *manifest_sha256,
                              const char *wasm_sha256, char *out, size_t size);

/* Lowercase hex SHA-256 of `data`. */
void cap_wasm_sha256_hex(const uint8_t *data, size_t len, char out[CAP_WASM_SHA_HEX_LEN + 1]);

/* Decodes a base64 raw 32-byte Ed25519 public key and derives its key_id. */
bool cap_wasm_key_parse(const char *b64, cap_wasm_key_t *out);

/*
 * Checks signature.json for the app `mf` describes: the format, sdk version, name and version
 * against the manifest, both hashes against the bytes, key_id against `keys` and the Ed25519
 * signature. On success `key_id` is the signing key's id.
 */
bool cap_wasm_sig_verify(const char *sig_json, const cap_wasm_manifest_t *mf,
                         const uint8_t *manifest, size_t manifest_len, const uint8_t *wasm, size_t wasm_len,
                         const cap_wasm_key_t *keys, size_t key_count,
                         char key_id[CAP_WASM_KEY_ID_LEN + 1], char *err, size_t err_size);

/*
 * Orders MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD] versions like semver: numeric fields, a
 * pre-release sorts before its release, pre-release identifiers compare numerically when both are
 * digits and as ASCII otherwise (digits first), build metadata is ignored. Returns false when
 * either version does not have that form; otherwise *out is <0, 0 or >0.
 */
bool cap_wasm_version_cmp(const char *a, const char *b, int *out);

/* Index of the least recently used loaded entry other than `skip`, or -1. */
int cap_wasm_lru_pick(const int64_t *last_used, const bool *loaded, size_t count, int skip);
