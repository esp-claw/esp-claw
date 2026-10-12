/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_release.h"

#include <stdio.h>
#include <string.h>

/* Scanner states between strings: the last string may be a key (a ':' follows), then its value. */
enum { SCAN_IDLE, SCAN_AFTER_STR, SCAN_VALUE };
enum { KEY_OTHER, KEY_TAG, KEY_URL, KEY_END };

static void scan_string_done(cap_wasm_rel_scan_t *s)
{
    s->str[s->str_len] = '\0';
    if (s->state != SCAN_VALUE) {
        s->key = strcmp(s->str, "tag_name") == 0 ? KEY_TAG : strcmp(s->str, "browser_download_url") == 0 ? KEY_URL :
                 strcmp(s->str, "tarball_url") == 0 ? KEY_END : KEY_OTHER;
        s->state = SCAN_AFTER_STR;
        return;
    }
    if (!s->overflow && s->key == KEY_TAG && s->str_len < sizeof(s->tag)) {
        strcpy(s->tag, s->str);
    } else if (!s->overflow && s->key == KEY_URL) {
        s->on_asset(s->ctx, s->str);
    }
    s->state = SCAN_IDLE;
}

void cap_wasm_rel_scan_feed(cap_wasm_rel_scan_t *s, const char *data, size_t len)
{
    for (size_t i = 0; i < len && !s->done; i++) {
        char c = data[i];

        if (++s->seen > CAP_WASM_REL_SCAN_MAX) {
            s->done = true;
        } else if (s->in_str && !s->esc && c == '"') {
            s->in_str = false;
            scan_string_done(s);
        } else if (s->in_str) {
            /* Escapes are kept as written; tags and URLs have none. */
            s->esc = !s->esc && c == '\\';
            if (s->str_len + 1 < sizeof(s->str)) {
                s->str[s->str_len++] = c;
            } else {
                s->overflow = true;
            }
        } else if (c == '"') {
            s->in_str = true;
            s->str_len = 0;
            s->overflow = false;
        } else if (c == ':' && s->state == SCAN_AFTER_STR) {
            /* Assets come before tarball_url; nothing after it is needed. */
            s->done = s->key == KEY_END;
            s->state = SCAN_VALUE;
        } else if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
            s->state = SCAN_IDLE;
        }
    }
}

/* True when the ';'-separated `list` contains `entry` (`len` bytes). */
static bool list_has(const char *list, const char *entry, size_t len)
{
    for (const char *p = list; *p; p += strcspn(p, ";"), p += *p == ';') {
        if (strcspn(p, ";") == len && strncmp(p, entry, len) == 0) {
            return true;
        }
    }
    return false;
}

bool cap_wasm_should_notify(const char *last, int64_t last_at, const char *cur, int64_t now)
{
    if (!cur[0]) {
        return false;
    }
    if (now - last_at >= CAP_WASM_NOTIFY_AGAIN_S) {
        return true;
    }
    for (const char *p = cur; *p; p += strcspn(p, ";"), p += *p == ';') {
        if (!list_has(last, p, strcspn(p, ";"))) {
            return true;
        }
    }
    return false;
}
