/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * esp-claw WASM app SDK, host API v1 (import module "claw").
 *
 * Freestanding C: no libc, no WASI. Build with apps/build.sh (clang --target=wasm32).
 *
 * An app exports three functions:
 *   void     app_init(void)                                  register tools here (budget 2 s)
 *   uint32_t app_alloc(uint32_t size)                        buffer for the next call's arguments
 *   int32_t  tool_call(int32_t tool, const char *args, uint32_t len)
 *            `tool` is the index returned by claw_tool_register(), `args` the JSON arguments the
 *            LLM passed (NUL-terminated, `len` excludes the NUL). Call claw_tool_result() once and
 *            return 0, or return non-zero for an error. Budget: limits.call_timeout_ms (5 s).
 *
 * Host functions return >= 0 on success and -CLAW_E* on failure. Every pointer/length pair is
 * bounds-checked by the host; an out-of-bounds buffer traps the call. A host function the
 * manifest does not grant (see manifest.json "permissions") makes the app fail to load.
 */
#ifndef CLAW_H
#define CLAW_H

#include <stdint.h>

#define CLAW_IMPORT(name) __attribute__((import_module("claw"), import_name(name)))
#define CLAW_EXPORT(name) __attribute__((export_name(name)))

/* Error codes, returned negated. */
#define CLAW_EPERM     1   /* not allowed (permission, wrong phase, profile not in manifest) */
#define CLAW_ENOENT    2   /* key or profile not found */
#define CLAW_EIO       5   /* I/O or transport error, rejected HTTP confirmation */
#define CLAW_E2BIG     7   /* argument too large */
#define CLAW_ENOMEM    12
#define CLAW_EEXIST    17  /* tool name already taken */
#define CLAW_EINVAL    22
#define CLAW_ENOSPC    28  /* key/tool limit or write budget reached, storage full */
#define CLAW_ENOTSUP   95  /* needs a Telegram request context */
#define CLAW_ENOBUFS   105 /* output buffer too small */
#define CLAW_ETIMEDOUT 110
#define CLAW_ECANCELED 125 /* user rejected the confirmation */

#define CLAW_LOG_ERROR 0
#define CLAW_LOG_WARN  1
#define CLAW_LOG_INFO  2
#define CLAW_LOG_DEBUG 3

/* permission "log": at most 32 lines per call, 512 bytes each. */
CLAW_IMPORT("log") void claw_log(int32_t level, const char *msg, uint32_t len);

/* Only in app_init. `name` becomes the LLM tool "<app>_<name>" ([a-z0-9_], <= 48 chars in
 * total); `desc` <= 256 bytes; `schema` a JSON Schema object <= 2048 bytes. At most 32 tools
 * across all apps. Returns the tool index passed to tool_call(). */
CLAW_IMPORT("tool_register") int32_t claw_tool_register(const char *name, uint32_t name_len,
                                                        const char *desc, uint32_t desc_len,
                                                        const char *schema, uint32_t schema_len);

/* Only in tool_call. Sets the tool's result text (<= 16 KB; the last call wins). */
CLAW_IMPORT("tool_result") int32_t claw_tool_result(const char *res, uint32_t len);

/* permission "kv": per-app persistent store. Keys 1-15 chars of [A-Za-z0-9_.-], values <= 1 KB,
 * <= 32 keys, <= 16 writes (set/del) per call. kv_get returns the value length,
 * -CLAW_ENOENT or -CLAW_ENOBUFS when out_cap is too small. */
CLAW_IMPORT("kv_get") int32_t claw_kv_get(const char *key, uint32_t key_len, void *out, uint32_t out_cap);
CLAW_IMPORT("kv_set") int32_t claw_kv_set(const char *key, uint32_t key_len, const void *val, uint32_t val_len);
CLAW_IMPORT("kv_del") int32_t claw_kv_del(const char *key, uint32_t key_len);

/* permission "http_profiles": request through a device credential profile listed in the manifest
 * (the device injects auth). `path_or_url` is "/path" (appended to the profile's base_url) or a full
 * https URL on the profile's hosts; `headers_json` a JSON object of strings or empty; `body` empty for
 * GET. Mutations (non-GET/HEAD) ask the user in Telegram and only work for requests from Telegram.
 * Returns the HTTP status or -errno. The response body (<= 32 KB; on error the error text) is read with
 * claw_http_response_read(), which returns the bytes copied and 0 at the end. Only in tool_call. */
CLAW_IMPORT("http_profile_request") int32_t claw_http_profile_request(const char *profile, uint32_t profile_len,
                                                                      const char *method, uint32_t method_len,
                                                                      const char *path_or_url, uint32_t url_len,
                                                                      const char *headers_json, uint32_t headers_len,
                                                                      const char *body, uint32_t body_len);
CLAW_IMPORT("http_response_read") int32_t claw_http_response_read(void *out, uint32_t out_cap);

/* permission "confirm": shows `text` with Yes/Cancel buttons in the originating Telegram chat and
 * waits up to 60 s. 0 = confirmed, -CLAW_ECANCELED, -CLAW_ETIMEDOUT, -CLAW_ENOTSUP outside Telegram. */
CLAW_IMPORT("confirm") int32_t claw_confirm(const char *text, uint32_t len);

/* Unix time in ms (before SNTP sync this is close to 0). */
CLAW_IMPORT("now_ms") int64_t claw_now_ms(void);

/* Fills buf with hardware random bytes. */
CLAW_IMPORT("random") int32_t claw_random(void *buf, uint32_t len);

/* ---- helpers ---- */

static inline uint32_t claw_strlen(const char *s)
{
    uint32_t n = 0;

    while (s[n]) {
        n++;
    }
    return n;
}

#define CLAW_S(s) (s), claw_strlen(s) /* pointer + length of a C string */

#define CLAW_LOG(level, s)        claw_log((level), CLAW_S(s))
#define CLAW_REGISTER(n, d, s)    claw_tool_register(CLAW_S(n), CLAW_S(d), CLAW_S(s))
#define CLAW_RESULT(s)            claw_tool_result(CLAW_S(s))

/* Single static buffer as app_alloc(): define CLAW_ARENA_SIZE (the largest accepted argument JSON)
 * before including claw.h and use CLAW_DEFINE_ARENA() once. Args are only valid during tool_call. */
#ifdef CLAW_ARENA_SIZE
#define CLAW_DEFINE_ARENA()                                                     \
    static uint8_t claw_arena_[CLAW_ARENA_SIZE];                                \
    CLAW_EXPORT("app_alloc") uint32_t app_alloc(uint32_t size)                  \
    {                                                                           \
        return size <= sizeof(claw_arena_) ? (uint32_t)(uintptr_t)claw_arena_ : 0; \
    }
#endif

#endif /* CLAW_H */
