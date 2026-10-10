/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Pure URL/host/redirect decisions used by cap_http_request (no ESP-IDF dependencies, so they
 * are covered by the host tests in test/host).
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Longest accepted redirect Location (Azure SAS / GitHub release asset URLs are ~1 KB). */
#define CAP_HTTP_REQUEST_REDIRECT_URL_MAX 2048

typedef enum {
    CAP_HTTP_REDIRECT_BLOCK,
    CAP_HTTP_REDIRECT_FOLLOW,
    CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH, /* follow, but drop the profile's auth header first */
} cap_http_redirect_t;

/* Host of an http(s) URL (without brackets, port or userinfo). */
bool cap_http_rules_url_host(const char *url, char *host, size_t host_size);
/* `pattern` is a host name, "*", "*.domain" (domain and subdomains) or ".domain" (same). */
bool cap_http_rules_host_matches(const char *host, const char *pattern);
/* Comma-separated allowlist of patterns; empty matches nothing. */
bool cap_http_rules_host_in_csv(const char *host, const char *csv);
/* JSON array of patterns. */
bool cap_http_rules_host_in_list(const char *host, const cJSON *hosts);
/* An https URL without whitespace, control bytes, backslashes or userinfo. */
bool cap_http_rules_https_url_ok(const char *url);
/* A redirect target that stays on https: such a URL, or a path ("/x", not "//x") on the current host. */
bool cap_http_rules_https_location_ok(const char *location);

/*
 * Decides how to follow a redirect to `location` from a request currently on `current_host`.
 * With `profile_hosts` (credential profile request) the target must pass
 * cap_http_rules_https_location_ok() and match `profile_hosts`; a host other than `origin_host`
 * (the host the credentials were sent to first) yields CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH.
 * Without it the target host must match the `allowlist` CSV. The target host is written to `host`.
 */
cap_http_redirect_t cap_http_rules_redirect(const char *location, const char *current_host,
                                            const char *origin_host, const cJSON *profile_hosts,
                                            const char *allowlist, char *host, size_t host_size);

/*
 * True when a POST to `url` matches one of the profile's "read_only_posts" patterns and so needs
 * no confirmation. A pattern starting with "/" matches the path after the profile's base_url, one
 * starting with "https://" the whole URL; query and fragment are ignored and "*" matches any run
 * of characters except "/". URLs with "%", "\" or a "/." sequence never match.
 */
bool cap_http_rules_read_only_post(const cJSON *profile, const char *url);

#ifdef __cplusplus
}
#endif
