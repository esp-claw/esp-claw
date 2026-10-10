/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * Minimal WebDAV (class 1+2) server mapping /dav/<path> onto the storage base
 * path, so the device can be mounted as a network drive.
 *
 * - Disabled (404) while webdav_password is empty; HTTP Basic auth otherwise.
 * - PROPFIND answers allprop for Depth 0/1 (infinity is treated as 1).
 * - LOCK/UNLOCK are fake: tokens are issued but never enforced. They only
 *   exist because Windows and macOS refuse to write without them.
 * - PROPPATCH accepts every property and stores nothing.
 * - Collections report RFC 4331 quota properties so clients can show free space.
 * - COPY supports files only; PUT bodies must carry Content-Length
 *   (esp_http_server cannot read chunked request bodies).
 */
#include "http_server_priv.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_vfs_fat.h"
#include "mbedtls/base64.h"

#define DAV_PREFIX       "/dav"
#define DAV_CRED_LEN     64
#define DAV_HDR_LEN      256
#define DAV_ALLOW        "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, COPY, MOVE, PROPFIND, PROPPATCH, LOCK, UNLOCK"
#define DAV_XML_HEAD     "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
#define DAV_XML_TYPE     "application/xml; charset=\"utf-8\""

static const char *TAG = "http_webdav";

static char s_user[DAV_CRED_LEN];
static char s_pass[DAV_CRED_LEN];

void http_server_webdav_apply_config(const app_config_t *config)
{
    strlcpy(s_user, config->webdav_user, sizeof(s_user));
    strlcpy(s_pass, config->webdav_password, sizeof(s_pass));
}

/* ── Responses ──────────────────────────────────────────────────────── */

static esp_err_t dav_status(httpd_req_t *req, const char *status)
{
    httpd_resp_set_status(req, status);
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t dav_send_raw(httpd_req_t *req, const char *buf, size_t len)
{
    while (len > 0) {
        int sent = httpd_send(req, buf, len);
        if (sent <= 0) {
            return ESP_FAIL;
        }
        buf += sent;
        len -= sent;
    }
    return ESP_OK;
}

/* ── Auth ───────────────────────────────────────────────────────────── */

static bool dav_authorized(httpd_req_t *req)
{
    char header[DAV_HDR_LEN];
    if (httpd_req_get_hdr_value_str(req, "Authorization", header, sizeof(header)) != ESP_OK ||
            strncasecmp(header, "Basic ", 6) != 0) {
        return false;
    }

    /* Compare full zero-padded buffers so timing does not depend on where
     * (or whether) the credentials differ. */
    unsigned char given[2 * DAV_CRED_LEN] = {0};
    char expected[2 * DAV_CRED_LEN] = {0};
    size_t given_len = 0;
    bool ok = mbedtls_base64_decode(given, sizeof(given) - 1, &given_len,
                                    (const unsigned char *)header + 6, strlen(header + 6)) == 0 &&
              memchr(given, '\0', given_len) == NULL;
    snprintf(expected, sizeof(expected), "%s:%s", s_user, s_pass);

    unsigned char diff = 0;
    for (size_t i = 0; i < sizeof(given); i++) {
        diff |= given[i] ^ (unsigned char)expected[i];
    }
    memset(given, 0, sizeof(given));
    memset(expected, 0, sizeof(expected));
    memset(header, 0, sizeof(header));
    return ok && diff == 0;
}

/* ── Paths ──────────────────────────────────────────────────────────── */

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Percent-decodes the part of a URL path after "/dav" into a storage-relative
 * path ("/" or "/a/b", no trailing slash). Rejects malformed escapes, NUL,
 * backslashes, empty segments and "." / ".." segments. */
static bool dav_decode_path(const char *src, size_t len, char *out, size_t out_size)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        if (c == '%') {
            int hi = i + 2 < len ? hex_value(src[i + 1]) : -1;
            int lo = i + 2 < len ? hex_value(src[i + 2]) : -1;
            if (hi < 0 || lo < 0) {
                return false;
            }
            c = (char)((hi << 4) | lo);
            i += 2;
        }
        if (c == '\0' || c == '\\' || o + 1 >= out_size) {
            return false;
        }
        out[o++] = c;
    }
    if (o > 1 && out[o - 1] == '/') {
        o--;
    }
    out[o] = '\0';
    if (o == 0 || (o == 1 && out[0] == '/')) {
        strlcpy(out, "/", out_size);
        return out_size > 1;
    }
    if (out[0] != '/') {
        return false;
    }

    for (const char *seg = out + 1; ; ) {
        const char *end = strchr(seg, '/');
        size_t seg_len = end ? (size_t)(end - seg) : strlen(seg);
        if (seg_len == 0 || (seg_len == 1 && seg[0] == '.') ||
                (seg_len == 2 && seg[0] == '.' && seg[1] == '.')) {
            return false;
        }
        if (!end) {
            return true;
        }
        seg = end + 1;
    }
}

/* Maps a storage-relative path to a filesystem path. The root maps to
 * "<base>/", the only spelling vfs_fat can stat and open for the volume root. */
static bool dav_full_path(const char *rel, char *full, size_t full_size)
{
    int n = snprintf(full, full_size, "%s%s", http_server_ctx()->storage_base_path, rel);
    return n > 0 && (size_t)n < full_size;
}

/* Parses the request URI (minus query) into rel/full paths. */
static bool dav_request_path(httpd_req_t *req, char *rel, char *full)
{
    const char *path = req->uri + strlen(DAV_PREFIX);
    size_t len = strcspn(path, "?#");
    return dav_decode_path(path, len, rel, HTTP_SERVER_PATH_MAX) &&
           dav_full_path(rel, full, HTTP_SERVER_PATH_MAX);
}

/* Parses the Destination header ("http://host/dav/x" or "/dav/x"). */
static bool dav_destination_path(httpd_req_t *req, char *rel, char *full)
{
    char dest[HTTP_SERVER_PATH_MAX * 2];
    if (httpd_req_get_hdr_value_str(req, "Destination", dest, sizeof(dest)) != ESP_OK) {
        return false;
    }
    const char *path = dest;
    const char *scheme = strstr(dest, "://");
    if (scheme) {
        path = strchr(scheme + 3, '/');
        if (!path) {
            return false;
        }
    }
    size_t prefix_len = strlen(DAV_PREFIX);
    if (strncmp(path, DAV_PREFIX, prefix_len) != 0 || (path[prefix_len] != '/' && path[prefix_len] != '\0')) {
        return false;
    }
    path += prefix_len;
    return dav_decode_path(path, strcspn(path, "?#"), rel, HTTP_SERVER_PATH_MAX) &&
           dav_full_path(rel, full, HTTP_SERVER_PATH_MAX);
}

static bool dav_is_root(const char *rel)
{
    return strcmp(rel, "/") == 0;
}

static bool dav_parent_is_dir(const char *full)
{
    char parent[HTTP_SERVER_PATH_MAX];
    strlcpy(parent, full, sizeof(parent));
    char *slash = strrchr(parent, '/');
    if (!slash) {
        return false;
    }
    /* Keep the slash only when the parent is the volume root ("<base>/"). */
    bool is_root = (size_t)(slash - parent) == strlen(http_server_ctx()->storage_base_path);
    slash[is_root ? 1 : 0] = '\0';
    struct stat st;
    return stat(parent, &st) == 0 && S_ISDIR(st.st_mode);
}

/* ── XML helpers ────────────────────────────────────────────────────── */

/* Appends src to buf[*pos] percent-encoding everything but unreserved
 * characters and '/'. Returns false when it does not fit. */
static bool append_href(char *buf, size_t size, size_t *pos, const char *src)
{
    static const char hex[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)src; *p; p++) {
        bool plain = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
                     strchr("/-._~", *p);
        if (*pos + (plain ? 1 : 3) >= size) {
            return false;
        }
        if (plain) {
            buf[(*pos)++] = (char)*p;
        } else {
            buf[(*pos)++] = '%';
            buf[(*pos)++] = hex[*p >> 4];
            buf[(*pos)++] = hex[*p & 0xF];
        }
    }
    buf[*pos] = '\0';
    return true;
}

static bool append_xml_text(char *buf, size_t size, size_t *pos, const char *src)
{
    for (const char *p = src; *p; p++) {
        const char *esc = *p == '&' ? "&amp;" : *p == '<' ? "&lt;" : *p == '>' ? "&gt;" :
                          *p == '"' ? "&quot;" : NULL;
        size_t n = esc ? strlen(esc) : 1;
        if (*pos + n >= size) {
            return false;
        }
        memcpy(buf + *pos, esc ? esc : p, n);
        *pos += n;
    }
    buf[*pos] = '\0';
    return true;
}

static bool append_fmt(char *buf, size_t size, size_t *pos, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf + *pos, size - *pos, fmt, args);
    va_end(args);
    if (n < 0 || (size_t)n >= size - *pos) {
        return false;
    }
    *pos += n;
    return true;
}

/* "/dav" + encoded rel (+ "/" for collections). */
static bool append_dav_href(char *buf, size_t size, size_t *pos, const char *rel, bool is_dir)
{
    return append_fmt(buf, size, pos, DAV_PREFIX) &&
           append_href(buf, size, pos, dav_is_root(rel) ? "" : rel) &&
           (!is_dir || append_fmt(buf, size, pos, "/"));
}

/* Files written before SNTP sync carry FAT's zero date (1980), the FAT root has no
 * timestamp at all (1970); such dates are omitted rather than shown. */
#define DAV_MIN_VALID_EPOCH 1577836800 /* 2020-01-01 */

static bool dav_time_valid(time_t t)
{
    return t >= DAV_MIN_VALID_EPOCH;
}

static void format_http_date(time_t t, char *out, size_t size)
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, size, "%a, %d %b %Y %H:%M:%S GMT", &tm);
}

static void format_etag(const struct stat *st, char *out, size_t size)
{
    snprintf(out, size, "\"%lx-%llx\"", (unsigned long)st->st_size, (unsigned long long)st->st_mtime);
}

static const char *content_type_for(const char *path)
{
    static const struct { const char *ext; const char *type; } types[] = {
        { ".txt", "text/plain" }, { ".md", "text/markdown" }, { ".lua", "text/plain" },
        { ".json", "application/json" }, { ".html", "text/html" }, { ".css", "text/css" },
        { ".js", "text/javascript" }, { ".png", "image/png" }, { ".jpg", "image/jpeg" },
        { ".jpeg", "image/jpeg" }, { ".gif", "image/gif" }, { ".svg", "image/svg+xml" },
        { ".pdf", "application/pdf" }, { ".wav", "audio/wav" }, { ".mp3", "audio/mpeg" },
    };
    const char *dot = strrchr(path, '.');
    for (size_t i = 0; dot && i < sizeof(types) / sizeof(types[0]); i++) {
        if (strcasecmp(dot, types[i].ext) == 0) {
            return types[i].type;
        }
    }
    return "application/octet-stream";
}

/* ── PROPFIND ───────────────────────────────────────────────────────── */

static esp_err_t propfind_send_entry(httpd_req_t *req, char *buf, const char *rel, const struct stat *st)
{
    const bool is_dir = S_ISDIR(st->st_mode);
    const char *name = dav_is_root(rel) ? "" : strrchr(rel, '/') + 1;
    char date[40];
    char created[24];
    char etag[40];
    struct tm tm;
    uint64_t fs_total = 0;
    uint64_t fs_free = 0;
    bool quota = is_dir && esp_vfs_fat_info(http_server_ctx()->storage_base_path, &fs_total, &fs_free) == ESP_OK;
    format_http_date(st->st_mtime, date, sizeof(date));
    gmtime_r(&st->st_mtime, &tm);
    strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%SZ", &tm);
    format_etag(st, etag, sizeof(etag));

    size_t pos = 0;
    const size_t size = HTTP_SERVER_SCRATCH_SIZE;
    bool ok = append_fmt(buf, size, &pos, "<D:response><D:href>") &&
              append_dav_href(buf, size, &pos, rel, is_dir) &&
              append_fmt(buf, size, &pos, "</D:href><D:propstat><D:prop><D:displayname>") &&
              append_xml_text(buf, size, &pos, name) &&
              append_fmt(buf, size, &pos,
                         "</D:displayname><D:resourcetype>%s</D:resourcetype>",
                         is_dir ? "<D:collection/>" : "") &&
              (!dav_time_valid(st->st_mtime) ||
               append_fmt(buf, size, &pos,
                          "<D:getlastmodified>%s</D:getlastmodified>"
                          "<D:creationdate>%s</D:creationdate>",
                          date, created)) &&
              (is_dir || append_fmt(buf, size, &pos,
                                    "<D:getcontentlength>%ld</D:getcontentlength>"
                                    "<D:getcontenttype>%s</D:getcontenttype>"
                                    "<D:getetag>%s</D:getetag>",
                                    (long)st->st_size, content_type_for(rel), etag)) &&
              (!quota || append_fmt(buf, size, &pos,
                                    "<D:quota-available-bytes>%llu</D:quota-available-bytes>"
                                    "<D:quota-used-bytes>%llu</D:quota-used-bytes>",
                                    (unsigned long long)fs_free,
                                    (unsigned long long)(fs_total - fs_free))) &&
              append_fmt(buf, size, &pos,
                         "<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>"
                         "<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>"
                         "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n");
    if (!ok) {
        return ESP_OK; /* cannot happen with PATH_MAX-bounded names; skip rather than truncate */
    }
    return httpd_resp_send_chunk(req, buf, pos);
}

static esp_err_t dav_propfind(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    if (stat(full, &st) != 0) {
        return dav_status(req, "404 Not Found");
    }

    char depth[16] = "1";
    httpd_req_get_hdr_value_str(req, "Depth", depth, sizeof(depth));
    DIR *dir = NULL;
    if (S_ISDIR(st.st_mode) && strcmp(depth, "0") != 0) {
        dir = opendir(full);
        if (!dir) {
            return dav_status(req, "500 Internal Server Error");
        }
    }

    char *buf = http_server_alloc_scratch_buffer();
    if (!buf) {
        if (dir) closedir(dir);
        return dav_status(req, "507 Insufficient Storage");
    }

    httpd_resp_set_status(req, "207 Multi-Status");
    httpd_resp_set_type(req, DAV_XML_TYPE);
    esp_err_t err = httpd_resp_send_chunk(req, DAV_XML_HEAD "<D:multistatus xmlns:D=\"DAV:\">\n", HTTPD_RESP_USE_STRLEN);
    if (err == ESP_OK) {
        err = propfind_send_entry(req, buf, rel, &st);
    }

    struct dirent *entry;
    while (err == ESP_OK && dir && (entry = readdir(dir)) != NULL) {
        char child_rel[HTTP_SERVER_PATH_MAX];
        char child_full[HTTP_SERVER_PATH_MAX];
        struct stat child_st;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 ||
                !http_server_build_child_relative_path(rel, entry->d_name, child_rel, sizeof(child_rel)) ||
                !dav_full_path(child_rel, child_full, sizeof(child_full)) ||
                stat(child_full, &child_st) != 0) {
            continue;
        }
        err = propfind_send_entry(req, buf, child_rel, &child_st);
    }

    if (dir) closedir(dir);
    free(buf);
    if (err == ESP_OK) {
        err = httpd_resp_send_chunk(req, "</D:multistatus>\n", HTTPD_RESP_USE_STRLEN);
    }
    return err == ESP_OK ? httpd_resp_send_chunk(req, NULL, 0) : ESP_FAIL;
}

/* ── PROPPATCH ──────────────────────────────────────────────────────── */

typedef struct {
    const char *prefix;
    size_t prefix_len;
    const char *uri;
    size_t uri_len;
} dav_ns_t;

/* Records xmlns / xmlns:p declarations found in the attribute text [p, end). */
static void collect_namespaces(const char *p, const char *end, dav_ns_t *ns, size_t *ns_count, size_t ns_max)
{
    while ((p = strstr(p, "xmlns")) != NULL && p < end && *ns_count < ns_max) {
        const char *prefix = p + 5;
        size_t prefix_len = 0;
        if (*prefix == ':') {
            prefix++;
            prefix_len = strcspn(prefix, "= \t\r\n");
        }
        const char *quote = strpbrk(prefix + prefix_len, "\"'");
        const char *close = quote ? strchr(quote + 1, *quote) : NULL;
        if (!close || close > end) {
            return;
        }
        if (!memchr(quote + 1, '"', close - quote - 1)) {
            ns[(*ns_count)++] = (dav_ns_t) { prefix, prefix_len, quote + 1, (size_t)(close - quote - 1) };
        }
        p = close + 1;
    }
}

static esp_err_t proppatch_send_prop(httpd_req_t *req, const char *name, size_t name_len,
                                     const dav_ns_t *ns, size_t ns_count)
{
    const char *colon = memchr(name, ':', name_len);
    size_t prefix_len = colon ? (size_t)(colon - name) : 0;
    const char *local = colon ? colon + 1 : name;
    size_t local_len = name_len - (local - name);
    const dav_ns_t *match = NULL;
    for (size_t i = ns_count; i-- > 0; ) {
        if (ns[i].prefix_len == prefix_len && strncmp(ns[i].prefix, name, prefix_len) == 0) {
            match = &ns[i];
            break;
        }
    }

    char out[384];
    int n = snprintf(out, sizeof(out), "<%.*s xmlns=\"%.*s\"/>", (int)local_len, local,
                     match ? (int)match->uri_len : 0, match ? match->uri : "");
    if (n <= 0 || (size_t)n >= sizeof(out)) {
        return ESP_OK;
    }
    return httpd_resp_send_chunk(req, out, n);
}

/* Echoes every property named in the request body back with 200 OK. */
static esp_err_t dav_proppatch(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    if (stat(full, &st) != 0) {
        return dav_status(req, "404 Not Found");
    }
    if (req->content_len >= HTTP_SERVER_SCRATCH_SIZE) {
        return dav_status(req, "413 Content Too Large");
    }

    char *body = http_server_alloc_scratch_buffer();
    if (!body) {
        return dav_status(req, "507 Insufficient Storage");
    }
    size_t len = 0;
    while (len < req->content_len) {
        int received = httpd_req_recv(req, body + len, req->content_len - len);
        if (received <= 0) {
            free(body);
            return ESP_FAIL;
        }
        len += received;
    }
    body[len] = '\0';

    char head[HTTP_SERVER_PATH_MAX * 3 + 128];
    size_t pos = 0;
    httpd_resp_set_status(req, "207 Multi-Status");
    httpd_resp_set_type(req, DAV_XML_TYPE);
    esp_err_t err = (append_fmt(head, sizeof(head), &pos,
                                DAV_XML_HEAD "<D:multistatus xmlns:D=\"DAV:\"><D:response><D:href>") &&
                     append_dav_href(head, sizeof(head), &pos, rel, S_ISDIR(st.st_mode)) &&
                     append_fmt(head, sizeof(head), &pos, "</D:href><D:propstat><D:prop>")) ?
                    httpd_resp_send_chunk(req, head, pos) : ESP_FAIL;

    /* Tiny tag scanner: every element directly inside a <prop> is a property. */
    dav_ns_t ns[8];
    size_t ns_count = 0;
    int depth = 0;
    int prop_depth = -1;
    for (const char *p = body; err == ESP_OK && (p = strchr(p, '<')) != NULL; ) {
        const char *gt = strchr(p, '>');
        if (!gt) {
            break;
        }
        if (p[1] == '?' || p[1] == '!') {
            p = gt + 1;
            continue;
        }
        const bool closing = p[1] == '/';
        const char *name = p + (closing ? 2 : 1);
        size_t name_len = strcspn(name, " \t\r\n/>");
        const char *colon = memchr(name, ':', name_len);
        const char *local = colon ? colon + 1 : name;
        const bool is_prop = (size_t)(name + name_len - local) == 4 && strncmp(local, "prop", 4) == 0;

        if (closing) {
            depth--;
            if (depth == prop_depth) {
                prop_depth = -1;
            }
        } else {
            collect_namespaces(name + name_len, gt, ns, &ns_count, sizeof(ns) / sizeof(ns[0]));
            if (prop_depth >= 0 && depth == prop_depth + 1) {
                err = proppatch_send_prop(req, name, name_len, ns, ns_count);
            } else if (prop_depth < 0 && is_prop) {
                prop_depth = depth;
            }
            if (gt[-1] != '/') {
                depth++;
            }
        }
        p = gt + 1;
    }
    free(body);

    if (err == ESP_OK) {
        err = httpd_resp_send_chunk(req, "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
                                    "</D:response></D:multistatus>\n", HTTPD_RESP_USE_STRLEN);
    }
    return err == ESP_OK ? httpd_resp_send_chunk(req, NULL, 0) : ESP_FAIL;
}

/* ── GET / HEAD ─────────────────────────────────────────────────────── */

static esp_err_t dav_get(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    if (stat(full, &st) != 0) {
        return dav_status(req, "404 Not Found");
    }
    if (S_ISDIR(st.st_mode)) {
        httpd_resp_set_hdr(req, "Allow", DAV_ALLOW);
        return dav_status(req, "405 Method Not Allowed");
    }

    int fd = req->method == HTTP_GET ? open(full, O_RDONLY) : -1;
    if (req->method == HTTP_GET && fd < 0) {
        return dav_status(req, "500 Internal Server Error");
    }
    char *buf = http_server_alloc_scratch_buffer();
    if (!buf) {
        if (fd >= 0) close(fd);
        return dav_status(req, "507 Insufficient Storage");
    }

    /* Headers are written by hand: esp_http_server only streams chunked
     * bodies and would add its own Content-Length to an empty HEAD reply. */
    char date[40];
    char last_modified[64] = "";
    char etag[40];
    if (dav_time_valid(st.st_mtime)) {
        format_http_date(st.st_mtime, date, sizeof(date));
        snprintf(last_modified, sizeof(last_modified), "Last-Modified: %s\r\n", date);
    }
    format_etag(&st, etag, sizeof(etag));
    int n = snprintf(buf, HTTP_SERVER_SCRATCH_SIZE,
                     "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n"
                     "%sETag: %s\r\n\r\n",
                     content_type_for(rel), (long)st.st_size, last_modified, etag);
    esp_err_t err = dav_send_raw(req, buf, n);

    while (err == ESP_OK && fd >= 0) {
        ssize_t got = read(fd, buf, HTTP_SERVER_SCRATCH_SIZE);
        if (got == 0) {
            break;
        }
        /* A read error after the headers can only be signalled by
         * dropping the connection. */
        err = got < 0 ? ESP_FAIL : dav_send_raw(req, buf, got);
    }

    if (fd >= 0) close(fd);
    free(buf);
    return err;
}

/* ── PUT / DELETE / MKCOL ───────────────────────────────────────────── */

static esp_err_t dav_put(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    const bool existed = stat(full, &st) == 0;
    if (existed && S_ISDIR(st.st_mode)) {
        return dav_status(req, "405 Method Not Allowed");
    }
    if (httpd_req_get_hdr_value_len(req, "Transfer-Encoding") > 0) {
        /* The chunked body is still on the socket; close it after replying. */
        httpd_resp_set_hdr(req, "Connection", "close");
        dav_status(req, "411 Length Required");
        return ESP_FAIL;
    }
    if (!dav_parent_is_dir(full)) {
        return dav_status(req, "409 Conflict");
    }

    char tmp[HTTP_SERVER_PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s" HTTP_SERVER_TMP_SUFFIX, full) >= (int)sizeof(tmp)) {
        return dav_status(req, "414 URI Too Long");
    }
    int rc = http_server_recv_to_file(req, tmp);
    if (rc != 0) {
        /* Unread body bytes may remain; close the connection after replying. */
        httpd_resp_set_hdr(req, "Connection", "close");
        dav_status(req, rc == ENOSPC ? "507 Insufficient Storage" : "500 Internal Server Error");
        return ESP_FAIL;
    }
    if (http_server_replace_file(tmp, full) != 0) {
        unlink(tmp);
        return dav_status(req, "500 Internal Server Error");
    }
    return dav_status(req, existed ? "204 No Content" : "201 Created");
}

static esp_err_t dav_delete(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    if (dav_is_root(rel)) {
        return dav_status(req, "403 Forbidden");
    }
    if (stat(full, &st) != 0) {
        return dav_status(req, "404 Not Found");
    }
    int rc = S_ISDIR(st.st_mode) ? http_server_rmdir_recursive(full) : unlink(full);
    return dav_status(req, rc == 0 ? "204 No Content" : "500 Internal Server Error");
}

static esp_err_t dav_mkcol(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    if (req->content_len > 0) {
        return dav_status(req, "415 Unsupported Media Type");
    }
    if (stat(full, &st) == 0) {
        return dav_status(req, "405 Method Not Allowed");
    }
    if (!dav_parent_is_dir(full)) {
        return dav_status(req, "409 Conflict");
    }
    return dav_status(req, mkdir(full, 0775) == 0 ? "201 Created" : "500 Internal Server Error");
}

/* ── COPY / MOVE ────────────────────────────────────────────────────── */

/* Copies src into a temp file next to dst and swaps it in. Returns 0 or errno. */
static int copy_file(const char *src, const char *dst)
{
    char tmp[HTTP_SERVER_PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s" HTTP_SERVER_TMP_SUFFIX, dst) >= (int)sizeof(tmp)) {
        return ENAMETOOLONG;
    }
    char *buf = http_server_alloc_scratch_buffer();
    int in = open(src, O_RDONLY);
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0664);
    int rc = (!buf || in < 0 || out < 0) ? EIO : 0;
    while (rc == 0) {
        ssize_t got = read(in, buf, HTTP_SERVER_SCRATCH_SIZE);
        if (got <= 0) {
            rc = got < 0 ? EIO : 0;
            break;
        }
        ssize_t written = write(out, buf, got);
        if (written != got) {
            rc = (written >= 0 || errno == ENOSPC) ? ENOSPC : EIO;
        }
    }
    if (out >= 0 && close(out) != 0 && rc == 0) {
        rc = EIO;
    }
    if (in >= 0) close(in);
    free(buf);
    if (rc == 0 && http_server_replace_file(tmp, dst) != 0) {
        rc = EIO;
    }
    if (rc != 0) {
        unlink(tmp);
    }
    return rc;
}

static esp_err_t dav_copy_move(httpd_req_t *req, const char *rel, const char *full)
{
    const bool move = req->method == HTTP_MOVE;
    char dst_rel[HTTP_SERVER_PATH_MAX];
    char dst_full[HTTP_SERVER_PATH_MAX];
    struct stat st;
    struct stat dst_st;
    if (!dav_destination_path(req, dst_rel, dst_full)) {
        return dav_status(req, "400 Bad Request");
    }
    if (dav_is_root(rel) || dav_is_root(dst_rel)) {
        return dav_status(req, "403 Forbidden");
    }
    if (stat(full, &st) != 0) {
        return dav_status(req, "404 Not Found");
    }
    size_t rel_len = strlen(rel);
    if (strcmp(rel, dst_rel) == 0 ||
            (S_ISDIR(st.st_mode) && strncmp(dst_rel, rel, rel_len) == 0 && dst_rel[rel_len] == '/')) {
        return dav_status(req, "403 Forbidden");
    }
    if (!move && S_ISDIR(st.st_mode)) {
        return dav_status(req, "501 Not Implemented");
    }
    if (!dav_parent_is_dir(dst_full)) {
        return dav_status(req, "409 Conflict");
    }

    char overwrite[4] = "T";
    httpd_req_get_hdr_value_str(req, "Overwrite", overwrite, sizeof(overwrite));
    const bool existed = stat(dst_full, &dst_st) == 0;
    if (existed && (overwrite[0] == 'F' || overwrite[0] == 'f')) {
        return dav_status(req, "412 Precondition Failed");
    }

    int rc;
    if (!move) {
        rc = copy_file(full, dst_full);
    } else if (existed && !S_ISDIR(st.st_mode) && !S_ISDIR(dst_st.st_mode)) {
        rc = http_server_replace_file(full, dst_full) == 0 ? 0 : EIO;
    } else {
        rc = 0;
        if (existed) {
            rc = (S_ISDIR(dst_st.st_mode) ? http_server_rmdir_recursive(dst_full) : unlink(dst_full)) == 0 ? 0 : EIO;
        }
        if (rc == 0 && rename(full, dst_full) != 0) {
            rc = EIO;
        }
    }

    if (rc != 0) {
        return dav_status(req, rc == ENOSPC ? "507 Insufficient Storage" : "500 Internal Server Error");
    }
    return dav_status(req, existed ? "204 No Content" : "201 Created");
}

/* ── LOCK / UNLOCK (not enforced) ───────────────────────────────────── */

static esp_err_t dav_lock(httpd_req_t *req, const char *rel, const char *full)
{
    struct stat st;
    bool created = false;
    if (stat(full, &st) != 0) {
        /* RFC 4918 9.10.4: locking an unmapped URL creates an empty file. */
        int fd = dav_parent_is_dir(full) ? open(full, O_WRONLY | O_CREAT, 0664) : -1;
        if (fd < 0) {
            return dav_status(req, "409 Conflict");
        }
        close(fd);
        st.st_mode = S_IFREG;
        created = true;
    }

    /* A refresh carries the existing token in the If header; echo it back. */
    char token[64] = {0};
    char if_hdr[DAV_HDR_LEN];
    const char *existing = NULL;
    if (httpd_req_get_hdr_value_str(req, "If", if_hdr, sizeof(if_hdr)) == ESP_OK) {
        existing = strstr(if_hdr, "opaquelocktoken:");
    }
    if (existing) {
        snprintf(token, sizeof(token), "%.*s", (int)strcspn(existing, ">) "), existing);
    } else {
        uint8_t r[16];
        esp_fill_random(r, sizeof(r));
        r[6] = (r[6] & 0x0F) | 0x40;
        r[8] = (r[8] & 0x3F) | 0x80;
        snprintf(token, sizeof(token),
                 "opaquelocktoken:%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
                 r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
    }

    char depth[16] = "0";
    httpd_req_get_hdr_value_str(req, "Depth", depth, sizeof(depth));
    char header[sizeof(token) + 2];
    snprintf(header, sizeof(header), "<%s>", token);

    char body[HTTP_SERVER_PATH_MAX * 3 + 512];
    size_t pos = 0;
    if (!(append_fmt(body, sizeof(body), &pos,
                     DAV_XML_HEAD "<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>"
                     "<D:locktype><D:write/></D:locktype><D:lockscope><D:exclusive/></D:lockscope>"
                     "<D:depth>%s</D:depth><D:timeout>Second-3600</D:timeout>"
                     "<D:locktoken><D:href>%s</D:href></D:locktoken><D:lockroot><D:href>",
                     strcmp(depth, "0") == 0 ? "0" : "infinity", token) &&
          append_dav_href(body, sizeof(body), &pos, rel, S_ISDIR(st.st_mode)) &&
          append_fmt(body, sizeof(body), &pos,
                     "</D:href></D:lockroot></D:activelock></D:lockdiscovery></D:prop>\n"))) {
        return dav_status(req, "500 Internal Server Error");
    }

    httpd_resp_set_status(req, created ? "201 Created" : "200 OK");
    httpd_resp_set_type(req, DAV_XML_TYPE);
    httpd_resp_set_hdr(req, "Lock-Token", header);
    return httpd_resp_send(req, body, pos);
}

/* ── Dispatch ───────────────────────────────────────────────────────── */

static esp_err_t webdav_handler(httpd_req_t *req)
{
    if (!s_pass[0]) {
        return httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, NULL);
    }
    if (!dav_authorized(req)) {
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"esp-claw\"");
        return dav_status(req, "401 Unauthorized");
    }

    char rel[HTTP_SERVER_PATH_MAX];
    char full[HTTP_SERVER_PATH_MAX];
    if (!dav_request_path(req, rel, full)) {
        return dav_status(req, "400 Bad Request");
    }

    switch (req->method) {
    case HTTP_OPTIONS:
        httpd_resp_set_hdr(req, "DAV", "1, 2");
        httpd_resp_set_hdr(req, "Allow", DAV_ALLOW);
        httpd_resp_set_hdr(req, "MS-Author-Via", "DAV");
        return dav_status(req, "200 OK");
    case HTTP_PROPFIND:
        return dav_propfind(req, rel, full);
    case HTTP_PROPPATCH:
        return dav_proppatch(req, rel, full);
    case HTTP_GET:
    case HTTP_HEAD:
        return dav_get(req, rel, full);
    case HTTP_PUT:
        return dav_put(req, rel, full);
    case HTTP_DELETE:
        return dav_delete(req, rel, full);
    case HTTP_MKCOL:
        return dav_mkcol(req, rel, full);
    case HTTP_COPY:
    case HTTP_MOVE:
        return dav_copy_move(req, rel, full);
    case HTTP_LOCK:
        return dav_lock(req, rel, full);
    case HTTP_UNLOCK:
        return dav_status(req, "204 No Content");
    default:
        httpd_resp_set_hdr(req, "Allow", DAV_ALLOW);
        return dav_status(req, "405 Method Not Allowed");
    }
}

esp_err_t http_server_register_webdav_routes(httpd_handle_t server)
{
    http_server_ctx_t *ctx = http_server_ctx();
    app_config_t *config = calloc(1, sizeof(*config));
    if (config && ctx->services.load_config(config) == ESP_OK) {
        http_server_webdav_apply_config(config);
    }
    free(config);
    ESP_LOGI(TAG, "WebDAV %s at " DAV_PREFIX "/", s_pass[0] ? "enabled" : "disabled (no webdav_password)");

    const httpd_uri_t handler = { .uri = DAV_PREFIX "/?*", .method = HTTP_ANY, .handler = webdav_handler };
    return httpd_register_uri_handler(server, &handler);
}
