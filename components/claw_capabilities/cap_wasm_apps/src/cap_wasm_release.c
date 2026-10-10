/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wasm_release.h"

#include <stdio.h>
#include <string.h>

#define ECAPP_SUFFIX ".ecapp"

/* Scanner states between strings: the last string may be a key (a ':' follows), then its value. */
enum { SCAN_IDLE, SCAN_AFTER_STR, SCAN_VALUE };
enum { KEY_OTHER, KEY_TAG, KEY_URL, KEY_END };

bool cap_wasm_gh_release_repo(const char *url, char *repo, size_t repo_size)
{
    static const char prefix[] = "https://github.com/";
    const char *owner = url + sizeof(prefix) - 1;
    const char *slash;
    const char *rel;

    if (strncmp(url, prefix, sizeof(prefix) - 1) != 0 || !(slash = strchr(owner, '/')) || slash == owner ||
            !(rel = strstr(slash + 1, "/releases/download/")) || rel == slash + 1 ||
            memchr(slash + 1, '/', rel - slash - 1) || (size_t)(rel - owner) >= repo_size) {
        return false;
    }
    memcpy(repo, owner, rel - owner);
    repo[rel - owner] = '\0';
    return true;
}

bool cap_wasm_ecapp_name_version(const char *file, char name[CAP_WASM_APP_NAME_MAX + 1],
                                 char version[CAP_WASM_VERSION_MAX + 1])
{
    const size_t suffix_len = sizeof(ECAPP_SUFFIX) - 1;
    const char *dash = strchr(file, '-');
    size_t len = strlen(file);
    size_t ver_len;

    if (!dash || len <= suffix_len || strcmp(file + len - suffix_len, ECAPP_SUFFIX) != 0 ||
            !cap_wasm_name_valid(file, dash - file, CAP_WASM_APP_NAME_MAX)) {
        return false;
    }
    /* App names have no '-' and the suffix none either, so the dash is before the suffix. */
    ver_len = (size_t)(file + len - suffix_len - dash - 1);
    if (ver_len == 0 || ver_len > CAP_WASM_VERSION_MAX) {
        return false;
    }
    memcpy(name, file, dash - file);
    name[dash - file] = '\0';
    memcpy(version, dash + 1, ver_len);
    version[ver_len] = '\0';
    return true;
}

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

void cap_wasm_rel_app_asset(void *ctx, const char *url)
{
    cap_wasm_rel_app_t *a = ctx;
    const char *file = strrchr(url, '/');
    const size_t suffix_len = sizeof(ECAPP_SUFFIX) - 1;
    size_t len = strlen(url);
    char name[CAP_WASM_APP_NAME_MAX + 1];
    char version[CAP_WASM_VERSION_MAX + 1];
    bool exact;

    if (!file || strncmp(url, "https://", 8) != 0 || len >= sizeof(a->url) || len <= suffix_len ||
            strcmp(url + len - suffix_len, ECAPP_SUFFIX) != 0) {
        return;
    }
    a->ecapps++;
    exact = cap_wasm_ecapp_name_version(file + 1, name, version) && strcmp(name, a->name) == 0;
    if (exact || (!a->exact && a->ecapps == 1)) {
        strcpy(a->url, url);
        strcpy(a->version, exact ? version : "");
        a->exact = exact;
    }
}

bool cap_wasm_rel_app_pick(cap_wasm_rel_app_t *a, const char *tag)
{
    if (!a->exact && a->ecapps != 1) {
        return false;
    }
    if (!a->version[0]) {
        snprintf(a->version, sizeof(a->version), "%s", tag + (tag[0] == 'v'));
    }
    return a->version[0] != '\0';
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
