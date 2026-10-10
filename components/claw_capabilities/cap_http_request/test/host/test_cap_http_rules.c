/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host tests for cap_http_rules.c; run with test/host/run.sh. */
#include <stdio.h>
#include <string.h>

#include "cap_http_rules.h"

static int s_failed;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

static cap_http_redirect_t redirect(const char *location, const char *current, const cJSON *hosts,
                                    const char *allowlist, char *host)
{
    return cap_http_rules_redirect(location, current, "api.github.com", hosts, allowlist, host, 128);
}

static void test_redirect_profile(void)
{
    cJSON *hosts = cJSON_Parse("[\"api.github.com\",\"*.blob.core.windows.net\"]");
    char host[128];
    char long_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX + 16];

    /* Same host keeps the credentials; host comparison ignores case. */
    CHECK(redirect("https://api.github.com/x", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(redirect("https://API.GitHub.com/x", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(redirect("/repos/x/logs", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(strcmp(host, "api.github.com") == 0);

    /* Allowed other host: follow without auth (GitHub job logs -> Azure blob SAS URL). */
    CHECK(redirect("https://pipelines.blob.core.windows.net/logs/1.txt?sv=2024&sig=abc%2Bdef", "api.github.com",
                   hosts, "", host) == CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH);
    CHECK(strcmp(host, "pipelines.blob.core.windows.net") == 0);
    /* A relative redirect on that host is still not the origin host. */
    CHECK(redirect("/next", "pipelines.blob.core.windows.net", hosts, "", host) ==
          CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH);

    /* Blocked: host outside the profile, downgrade, protocol-relative, userinfo, junk, overlong. */
    CHECK(redirect("https://evil.example/x", "api.github.com", hosts, "*", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("http://api.github.com/x", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("//api.github.com/x", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("https://evil.example@api.github.com/x", "api.github.com", hosts, "", host) ==
          CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("https://api.github.com\\@evil.example/", "api.github.com", hosts, "", host) ==
          CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("relative/path", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("ftp://api.github.com/x", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("", "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("https://blob.core.windows.net.evil.example/", "api.github.com", hosts, "", host) ==
          CAP_HTTP_REDIRECT_BLOCK);

    /* Long signed URLs up to the limit are fine, longer ones are refused. */
    memset(long_url, 'a', sizeof(long_url));
    memcpy(long_url, "https://x.blob.core.windows.net/", 32);
    long_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX - 1] = '\0';
    CHECK(redirect(long_url, "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_FOLLOW_NO_AUTH);
    long_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX - 1] = 'a';
    long_url[CAP_HTTP_REQUEST_REDIRECT_URL_MAX] = '\0';
    CHECK(redirect(long_url, "api.github.com", hosts, "", host) == CAP_HTTP_REDIRECT_BLOCK);

    cJSON_Delete(hosts);
}

static void test_redirect_allowlist(void)
{
    char host[128];

    CHECK(redirect("http://example.com/x", "a.org", NULL, "example.com, *.a.org", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(redirect("//www.a.org/x", "a.org", NULL, "example.com,*.a.org", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(redirect("/x", "a.org", NULL, "*.a.org", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(redirect("https://b.org/x", "a.org", NULL, "a.org", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("https://b.org/x", "a.org", NULL, "", host) == CAP_HTTP_REDIRECT_BLOCK);
    CHECK(redirect("https://[::1]:8443/x", "a.org", NULL, "[::1]", host) == CAP_HTTP_REDIRECT_FOLLOW);
    CHECK(strcmp(host, "::1") == 0);
}

static void test_hosts(void)
{
    char host[64];

    CHECK(cap_http_rules_url_host("https://user@Example.com:443/p?q", host, sizeof(host)) &&
          strcmp(host, "Example.com") == 0);
    CHECK(!cap_http_rules_url_host("ftp://example.com/", host, sizeof(host)));
    CHECK(cap_http_rules_host_matches("a.b.example.com", "*.example.com"));
    CHECK(cap_http_rules_host_matches("example.com", ".example.com"));
    CHECK(!cap_http_rules_host_matches("badexample.com", "*.example.com"));
    CHECK(cap_http_rules_https_url_ok("https://api.tavily.com/search"));
    CHECK(!cap_http_rules_https_url_ok("https://a b/"));
    CHECK(cap_http_rules_https_location_ok("/download/x?sig=1"));
    CHECK(!cap_http_rules_https_location_ok("http://example.com/"));
}

static void test_read_only_posts(void)
{
    cJSON *cf = cJSON_Parse("{\"base_url\":\"https://api.cloudflare.com/client/v4/\","
                            "\"read_only_posts\":[\"/graphql\"]}");
    cJSON *gcp = cJSON_Parse("{\"base_url\":\"https://apigee.googleapis.com\","
                             "\"read_only_posts\":[\"/v1/projects/*/analytics/endpoints/logs*\"]}");
    cJSON *none = cJSON_Parse("{\"base_url\":\"https://api.tavily.com\"}");
    cJSON *logs = cJSON_Parse("{\"base_url\":\"https://compute.googleapis.com\","
                              "\"read_only_posts\":[\"https://logging.googleapis.com/v2/entries:list\"]}");

    CHECK(cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/graphql"));
    CHECK(cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/graphql?x=1"));
    CHECK(!cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/graphql/x"));
    CHECK(!cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/zones/1/purge_cache"));
    CHECK(!cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/graphql"));
    CHECK(!cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/graphql/../zones"));
    CHECK(!cap_http_rules_read_only_post(cf, "https://api.cloudflare.com/client/v4/%67raphql"));

    CHECK(cap_http_rules_read_only_post(gcp, "https://apigee.googleapis.com/v1/projects/p1/analytics/endpoints/logs"));
    CHECK(cap_http_rules_read_only_post(gcp, "https://apigee.googleapis.com/v1/projects/p1/analytics/endpoints/logs:query"));
    CHECK(!cap_http_rules_read_only_post(gcp, "https://apigee.googleapis.com/v1/projects/p1/x/analytics/endpoints/logs"));
    CHECK(!cap_http_rules_read_only_post(gcp, "https://apigee.googleapis.com/v1/projects/p1/analytics/endpoints/logs/delete"));

    CHECK(!cap_http_rules_read_only_post(none, "https://api.tavily.com/search"));

    CHECK(cap_http_rules_read_only_post(logs, "https://logging.googleapis.com/v2/entries:list"));
    CHECK(!cap_http_rules_read_only_post(logs, "https://logging.googleapis.com/v2/entries:write"));
    CHECK(!cap_http_rules_read_only_post(logs, "https://compute.googleapis.com/v2/entries:list"));

    cJSON_Delete(cf);
    cJSON_Delete(gcp);
    cJSON_Delete(none);
    cJSON_Delete(logs);
}

int main(void)
{
    test_redirect_profile();
    test_redirect_allowlist();
    test_hosts();
    test_read_only_posts();
    printf("%s\n", s_failed ? "FAILED" : "OK");
    return s_failed ? 1 : 0;
}
