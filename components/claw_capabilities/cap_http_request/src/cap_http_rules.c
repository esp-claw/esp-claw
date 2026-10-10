/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_http_rules.h"

#include <string.h>
#include <strings.h>

/* Host of the authority starting at `authority` (after "scheme://" or "//"). */
static bool cap_http_rules_authority_host(const char *authority, char *host, size_t host_size)
{
    const char *authority_end = authority + strcspn(authority, "/?#");
    const char *start = authority;
    const char *host_end = NULL;
    size_t host_len;

    for (const char *p = authority; p < authority_end; p++) {
        if (*p == '@') {
            start = p + 1;
        }
    }
    if (start >= authority_end) {
        return false;
    }
    if (*start == '[') {
        host_end = memchr(start + 1, ']', (size_t)(authority_end - start - 1));
        if (!host_end || host_end == start + 1) {
            return false;
        }
        start++;
    } else {
        host_end = start;
        while (host_end < authority_end && *host_end != ':') {
            host_end++;
        }
        if (host_end <= start) {
            return false;
        }
    }
    host_len = (size_t)(host_end - start);
    if (host_len + 1 > host_size) {
        return false;
    }
    memcpy(host, start, host_len);
    host[host_len] = '\0';
    return true;
}

bool cap_http_rules_url_host(const char *url, char *host, size_t host_size)
{
    if (!url || !host || host_size == 0) {
        return false;
    }
    host[0] = '\0';
    if (strncasecmp(url, "http://", 7) == 0) {
        return cap_http_rules_authority_host(url + 7, host, host_size);
    }
    if (strncasecmp(url, "https://", 8) == 0) {
        return cap_http_rules_authority_host(url + 8, host, host_size);
    }
    return false;
}

bool cap_http_rules_host_matches(const char *host, const char *pattern)
{
    size_t host_len;
    size_t pattern_len;

    if (!host || !pattern || !host[0] || !pattern[0]) {
        return false;
    }
    host_len = strlen(host);
    pattern_len = strlen(pattern);

    if (pattern_len == 1 && pattern[0] == '*') {
        return true;
    }
    if (pattern_len >= 3 && pattern[0] == '*' && pattern[1] == '.') {
        pattern++;
        pattern_len--;
    }
    if (pattern[0] == '.') {
        return strcasecmp(host, pattern + 1) == 0 ||
               (host_len > pattern_len && strcasecmp(host + host_len - pattern_len, pattern) == 0);
    }
    return strcasecmp(host, pattern) == 0;
}

bool cap_http_rules_host_in_csv(const char *host, const char *csv)
{
    char token[256];

    if (!host || !host[0] || !csv) {
        return false;
    }
    while (*csv) {
        const char *start = csv;
        const char *end = start + strcspn(start, ",");
        size_t len;

        csv = *end ? end + 1 : end;
        while (start < end && strchr(" \t\r\n", *start)) {
            start++;
        }
        while (end > start && strchr(" \t\r\n", end[-1])) {
            end--;
        }
        if (end - start >= 2 && *start == '[' && end[-1] == ']') {
            start++;
            end--;
        }
        len = (size_t)(end - start);
        if (len == 0 || len >= sizeof(token)) {
            continue;
        }
        memcpy(token, start, len);
        token[len] = '\0';
        if (cap_http_rules_host_matches(host, token)) {
            return true;
        }
    }
    return false;
}

bool cap_http_rules_host_in_list(const char *host, const cJSON *hosts)
{
    const cJSON *item = NULL;

    cJSON_ArrayForEach(item, hosts) {
        if (cJSON_IsString(item) && cap_http_rules_host_matches(host, item->valuestring)) {
            return true;
        }
    }
    return false;
}

/* Profile URLs must not contain whitespace, control bytes, backslashes, or userinfo, so this
 * parser and esp_http_client cannot disagree on the host the credentials are sent to. */
bool cap_http_rules_https_url_ok(const char *url)
{
    const char *authority;

    if (!url || strncasecmp(url, "https://", 8) != 0) {
        return false;
    }
    for (const char *p = url; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f || *p == '\\') {
            return false;
        }
    }
    authority = url + 8;
    return memchr(authority, '@', strcspn(authority, "/?#")) == NULL;
}

bool cap_http_rules_https_location_ok(const char *location)
{
    if (!location) {
        return false;
    }
    if (strncasecmp(location, "https://", 8) == 0) {
        return cap_http_rules_https_url_ok(location);
    }
    for (const char *p = location; *p; p++) {
        if ((unsigned char)*p <= 0x20 || *p == 0x7f || *p == '\\') {
            return false;
        }
    }
    return location[0] == '/' && location[1] != '/';
}

cap_http_redirect_t cap_http_rules_redirect(const char *location, const char *current_host,
                                            const char *origin_host, const cJSON *profile_hosts,
                                            const char *allowlist, char *host, size_t host_size)
{
    const char *scheme;

    if (!location || !location[0] || strlen(location) >= CAP_HTTP_REQUEST_REDIRECT_URL_MAX ||
            !current_host || !host || host_size == 0) {
        return CAP_HTTP_REDIRECT_BLOCK;
    }
    host[0] = '\0';
    scheme = strstr(location, "://");
    if (scheme && (size_t)(scheme - location) < strcspn(location, "/?#")) {
        if (!cap_http_rules_url_host(location, host, host_size)) {
            return CAP_HTTP_REDIRECT_BLOCK; /* not http(s) */
        }
    } else if (location[0] == '/' && location[1] == '/') {
        if (!cap_http_rules_authority_host(location + 2, host, host_size)) {
            return CAP_HTTP_REDIRECT_BLOCK;
        }
    } else if (strlen(current_host) < host_size) {
        strcpy(host, current_host);
    } else {
        return CAP_HTTP_REDIRECT_BLOCK;
    }

    if (!profile_hosts) {
        return cap_http_rules_host_in_csv(host, allowlist) ? CAP_HTTP_REDIRECT_FOLLOW : CAP_HTTP_REDIRECT_BLOCK;
    }
    if (!cap_http_rules_https_location_ok(location) || !cap_http_rules_host_in_list(host, profile_hosts)) {
        return CAP_HTTP_REDIRECT_BLOCK;
    }
    return origin_host && strcasecmp(host, origin_host) == 0 ?
           CAP_HTTP_REDIRECT_FOLLOW : CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH;
}

/* Glob match of pattern against text[0..len): "*" matches any run of characters except "/". */
static bool cap_http_rules_glob(const char *pattern, const char *text, size_t len)
{
    if (!*pattern) {
        return len == 0;
    }
    if (*pattern == '*') {
        for (size_t i = 0;; i++) {
            if (cap_http_rules_glob(pattern + 1, text + i, len - i)) {
                return true;
            }
            if (i == len || text[i] == '/') {
                return false;
            }
        }
    }
    return len > 0 && *pattern == *text && cap_http_rules_glob(pattern + 1, text + 1, len - 1);
}

bool cap_http_rules_read_only_post(const cJSON *profile, const char *url)
{
    const char *base_url = cJSON_GetStringValue(cJSON_GetObjectItem(profile, "base_url"));
    const cJSON *pattern = NULL;
    const char *path = NULL;
    size_t url_len;
    size_t base_len;

    if (!base_url || !url) {
        return false;
    }
    url_len = strcspn(url, "?#");
    for (size_t i = 0; i < url_len; i++) {
        if (url[i] == '%' || url[i] == '\\' || (url[i] == '/' && url[i + 1] == '.')) {
            return false;
        }
    }
    base_len = strlen(base_url);
    while (base_len > 0 && base_url[base_len - 1] == '/') {
        base_len--;
    }
    if (strncmp(url, base_url, base_len) == 0 && url[base_len] == '/') {
        path = url + base_len;
    }
    cJSON_ArrayForEach(pattern, cJSON_GetObjectItem(profile, "read_only_posts")) {
        const char *p = cJSON_GetStringValue(pattern);

        if (p && p[0] == '/' && path && cap_http_rules_glob(p, path, url_len - base_len)) {
            return true;
        }
        if (p && strncmp(p, "https://", 8) == 0 && cap_http_rules_glob(p, url, url_len)) {
            return true;
        }
    }
    return false;
}
