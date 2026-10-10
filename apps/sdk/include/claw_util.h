/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Optional helpers for esp-claw WASM apps: an output buffer and a minimal JSON reader for
 * well-formed input (tool arguments, API responses). Header-only, freestanding.
 */
#ifndef CLAW_UTIL_H
#define CLAW_UTIL_H

#include <stdint.h>

#include "claw.h" /* claw_strlen() */

/* ---- output buffer (silently stops at cap; `full` tells) ---- */

typedef struct {
    char *buf;
    uint32_t cap;
    uint32_t len;
    int full;
} claw_buf_t;

static inline void cb_putn(claw_buf_t *b, const char *s, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) {
        if (b->len + 1 >= b->cap) {
            b->full = 1;
            return;
        }
        b->buf[b->len++] = s[i];
    }
    b->buf[b->len] = '\0';
}

static inline void cb_put(claw_buf_t *b, const char *s)
{
    cb_putn(b, s, claw_strlen(s));
}

static inline void cb_put_u32(claw_buf_t *b, uint32_t v)
{
    char tmp[10];
    char out[10];
    int n = 0;
    int i = 0;

    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) {
        out[i++] = tmp[--n];
    }
    cb_putn(b, out, (uint32_t)i);
}

/* Appends `n` bytes as JSON string contents (escapes quotes, backslashes and control bytes). */
static inline void cb_put_escaped(claw_buf_t *b, const char *s, uint32_t n)
{
    static const char hex[] = "0123456789abcdef";

    for (uint32_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        char esc[6] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf] };

        if (c == '"' || c == '\\') {
            esc[1] = (char)c;
            cb_putn(b, esc, 2);
        } else if (c < 0x20) {
            cb_putn(b, esc, 6);
        } else {
            cb_putn(b, (const char *)&s[i], 1);
        }
    }
}

/* ---- JSON reader: pointers into the source text, `end` is one past the last byte ---- */

static inline const char *cj_ws(const char *p, const char *end)
{
    while (p < end && (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')) {
        p++;
    }
    return p;
}

/* Skips one value starting at p (after whitespace); returns the byte after it or 0. */
static inline const char *cj_skip(const char *p, const char *end)
{
    int depth = 0;

    p = cj_ws(p, end);
    do {
        if (p >= end) {
            return 0;
        }
        if (*p == '"') {
            for (p++; p < end && *p != '"'; p++) {
                if (*p == '\\') {
                    p++;
                }
            }
            if (p >= end) {
                return 0;
            }
        } else if (*p == '{' || *p == '[') {
            depth++;
        } else if (*p == '}' || *p == ']') {
            depth--;
        } else if (depth == 0) {
            while (p + 1 < end && p[1] != ',' && p[1] != '}' && p[1] != ']' &&
                    p[1] != ' ' && p[1] != '\n' && p[1] != '\r' && p[1] != '\t') {
                p++;
            }
        }
        p++;
    } while (depth > 0);
    return p;
}

/* Value of top-level member `key` of the object at `obj` ('{'), or 0. */
static inline const char *cj_member(const char *obj, const char *end, const char *key)
{
    uint32_t klen = claw_strlen(key);
    const char *p = cj_ws(obj, end);

    if (p >= end || *p != '{') {
        return 0;
    }
    for (p = cj_ws(p + 1, end); p && p < end && *p == '"'; p = cj_ws(p, end)) {
        const char *k = p + 1;
        const char *v;
        uint32_t i;

        p = cj_skip(p, end);
        if (!p) {
            return 0;
        }
        for (i = 0; i < klen && k + i < end && k[i] == key[i]; i++) {
        }
        p = cj_ws(p, end);
        if (p >= end || *p != ':') {
            return 0;
        }
        v = cj_ws(p + 1, end);
        if (i == klen && k[klen] == '"') {
            return v;
        }
        p = cj_ws(cj_skip(v, end), end);
        if (!p || p >= end || *p != ',') {
            return 0;
        }
        p++;
    }
    return 0;
}

/* First element of the array at `list` ('['), or 0 when empty / not an array. */
static inline const char *cj_first(const char *list, const char *end)
{
    const char *p = cj_ws(list, end);

    if (!p || p >= end || *p != '[') {
        return 0;
    }
    p = cj_ws(p + 1, end);
    return p < end && *p != ']' ? p : 0;
}

/* Element after `item` in its array, or 0 at the end. */
static inline const char *cj_next(const char *item, const char *end)
{
    const char *p = cj_skip(item, end);

    p = p ? cj_ws(p, end) : 0;
    if (!p || p >= end || *p != ',') {
        return 0;
    }
    p = cj_ws(p + 1, end);
    return p < end ? p : 0;
}

/* Copies the raw contents of the string value at v (escapes kept as-is, so the result can be
 * re-emitted inside a JSON string). Returns the length, or -1 if v is not a string or too long. */
static inline int32_t cj_string(const char *v, const char *end, char *out, uint32_t cap)
{
    const char *close;
    uint32_t n;

    if (!v || v >= end || *v != '"' || !(close = cj_skip(v, end))) {
        return -1;
    }
    n = (uint32_t)(close - v - 2);
    if (n + 1 > cap) {
        return -1;
    }
    for (uint32_t i = 0; i < n; i++) {
        out[i] = v[1 + i];
    }
    out[n] = '\0';
    return (int32_t)n;
}

/* Parses a non-negative integer value at v; returns -1 if there is none. */
static inline int64_t cj_uint(const char *v, const char *end)
{
    int64_t n = 0;
    const char *p = v;

    for (; p && p < end && *p >= '0' && *p <= '9'; p++) {
        n = n * 10 + (*p - '0');
    }
    return p && p != v ? n : -1;
}

#endif /* CLAW_UTIL_H */
