/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * cf_dns: read-only Cloudflare DNS through the device's "cloudflare" API profile.
 *   cf_dns_zones    list zones (name, id, status)
 *   cf_dns_records  list a zone's DNS records (name, type, content)
 * The device injects the API token; the app never sees it.
 */
#define CLAW_ARENA_SIZE 1024
#include "claw.h"
#include "claw_util.h"

CLAW_DEFINE_ARENA()

#define PAGE_SIZE 40 /* keeps a records page well below the 32 KB response cap */
#define MAX_PAGES 10
#define CLOSE_RESERVE 64

static int32_t s_zones = -1;
static int32_t s_records = -1;
static char s_resp[32 * 1024 + 1];
static uint32_t s_resp_len;
static char s_out[16 * 1024];

CLAW_EXPORT("app_init") void app_init(void)
{
    s_zones = CLAW_REGISTER("zones", "List the Cloudflare zones (domains) of the configured account: name, id, status.",
                            "{\"type\":\"object\",\"properties\":{}}");
    s_records = CLAW_REGISTER("records", "List the DNS records of a Cloudflare zone as name/type/content.",
                              "{\"type\":\"object\",\"properties\":{\"zone_name\":{\"type\":\"string\","
                              "\"description\":\"Zone (domain) name, e.g. example.com\"}},\"required\":[\"zone_name\"]}");
}

/* GET through the profile; the body lands in s_resp. Returns the HTTP status or -errno. */
static int32_t cf_get(const char *path, uint32_t path_len)
{
    int32_t rc = claw_http_profile_request(CLAW_S("cloudflare"), CLAW_S("GET"), path, path_len, "", 0, "", 0);
    int32_t n;

    s_resp_len = 0;
    while ((n = claw_http_response_read(s_resp + s_resp_len, sizeof(s_resp) - 1 - s_resp_len)) > 0) {
        s_resp_len += (uint32_t)n;
    }
    s_resp[s_resp_len] = '\0';
    return rc;
}

/* Reports a failed request with Cloudflare's "errors" array or the device's error text. */
static void fail(const char *what, int32_t rc)
{
    claw_buf_t b = { s_out, sizeof(s_out), 0, 0 };
    const char *end = s_resp + s_resp_len;
    const char *errors = cj_member(s_resp, end, "errors");
    const char *errors_end = errors ? cj_skip(errors, end) : 0;

    cb_put(&b, "{\"error\":\"");
    cb_put(&b, what);
    cb_put(&b, " failed\",\"status\":");
    if (rc < 0) {
        cb_put(&b, "-");
        rc = -rc;
    }
    cb_put_u32(&b, (uint32_t)rc);
    if (errors_end) {
        cb_put(&b, ",\"errors\":");
        cb_putn(&b, errors, (uint32_t)(errors_end - errors));
    } else {
        cb_put(&b, ",\"detail\":\"");
        cb_put_escaped(&b, s_resp, s_resp_len < 300 ? s_resp_len : 300);
        cb_put(&b, "\"");
    }
    cb_put(&b, "}");
    claw_tool_result(b.buf, b.len);
}

/* Appends {"<k>":"<v>",...} for the given string members of the object at item. */
static void put_fields(claw_buf_t *b, const char *item, const char *end, const char *const *keys, int count)
{
    char val[512];

    cb_put(b, "{");
    for (int i = 0; i < count; i++) {
        int32_t n = cj_string(cj_member(item, end, keys[i]), end, val, sizeof(val));

        cb_put(b, i ? ",\"" : "\"");
        cb_put(b, keys[i]);
        cb_put(b, "\":\"");
        cb_putn(b, val, n > 0 ? (uint32_t)n : 0);
        cb_put(b, "\"");
    }
    cb_put(b, "}");
}

/* Appends the elements of the response's "result" array that fit completely, leaving
 * CLOSE_RESERVE bytes for the closing text; returns how many. */
static uint32_t put_results(claw_buf_t *b, const char *const *keys, int count, uint32_t done)
{
    const char *end = s_resp + s_resp_len;
    uint32_t cap = b->cap;
    uint32_t n = 0;

    b->cap = cap - CLOSE_RESERVE;
    for (const char *item = cj_first(cj_member(s_resp, end, "result"), end); item && !b->full;
            item = cj_next(item, end)) {
        uint32_t mark = b->len;

        cb_put(b, done + n ? "," : "");
        put_fields(b, item, end, keys, count);
        if (b->full) {
            b->len = mark;
            b->buf[mark] = '\0';
            break;
        }
        n++;
    }
    b->cap = cap;
    return n;
}

static void tool_zones(void)
{
    static const char *const keys[] = { "name", "id", "status" };
    claw_buf_t b = { s_out, sizeof(s_out), 0, 0 };
    int32_t rc = cf_get(CLAW_S("/zones?per_page=50"));

    if (rc != 200) {
        fail("GET /zones", rc);
        return;
    }
    cb_put(&b, "[");
    put_results(&b, keys, 3, 0);
    cb_put(&b, "]");
    claw_tool_result(b.buf, b.len);
}

static void tool_records(const char *args, const char *end)
{
    static const char *const keys[] = { "name", "type", "content" };
    claw_buf_t b = { s_out, sizeof(s_out), 0, 0 };
    char zone[256];
    char id[64];
    char path[384];
    claw_buf_t p = { path, sizeof(path), 0, 0 };
    int32_t zone_len = cj_string(cj_member(args, end, "zone_name"), end, zone, sizeof(zone));
    const char *resp_end;
    uint32_t count = 0;
    int64_t pages = 1;
    int32_t rc;

    /* Only host name characters, so the name cannot inject query parameters. */
    for (int32_t i = 0; i < zone_len; i++) {
        char c = zone[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            zone_len = -1;
        }
    }
    if (zone_len <= 0) {
        CLAW_RESULT("{\"error\":\"zone_name must be a domain name\"}");
        return;
    }

    cb_put(&p, "/zones?per_page=1&name=");
    cb_put(&p, zone);
    rc = cf_get(p.buf, p.len);
    resp_end = s_resp + s_resp_len;
    if (rc != 200) {
        fail("zone lookup", rc);
        return;
    }
    if (cj_string(cj_member(cj_first(cj_member(s_resp, resp_end, "result"), resp_end), resp_end, "id"),
                  resp_end, id, sizeof(id)) <= 0) {
        cb_put(&b, "{\"error\":\"zone not found\",\"zone\":\"");
        cb_put(&b, zone);
        cb_put(&b, "\"}");
        claw_tool_result(b.buf, b.len);
        return;
    }

    cb_put(&b, "{\"zone\":\"");
    cb_put(&b, zone);
    cb_put(&b, "\",\"records\":[");
    for (int64_t page = 1; page <= pages && page <= MAX_PAGES && !b.full; page++) {
        p.len = 0;
        cb_put(&p, "/zones/");
        cb_put(&p, id);
        cb_put(&p, "/dns_records?per_page=");
        cb_put_u32(&p, PAGE_SIZE);
        cb_put(&p, "&page=");
        cb_put_u32(&p, (uint32_t)page);
        rc = cf_get(p.buf, p.len);
        if (rc != 200) {
            fail("GET dns_records", rc);
            return;
        }
        resp_end = s_resp + s_resp_len;
        pages = cj_uint(cj_member(cj_member(s_resp, resp_end, "result_info"), resp_end, "total_pages"), resp_end);
        count += put_results(&b, keys, 3, count);
    }
    cb_put(&b, "],\"count\":");
    cb_put_u32(&b, count);
    cb_put(&b, b.full || pages > MAX_PAGES ? ",\"truncated\":true}" : "}");
    claw_tool_result(b.buf, b.len);
}

CLAW_EXPORT("tool_call") int32_t tool_call(int32_t tool, const char *args, uint32_t len)
{
    if (tool == s_zones) {
        tool_zones();
    } else if (tool == s_records) {
        tool_records(args, args + len);
    } else {
        return -1;
    }
    return 0;
}
