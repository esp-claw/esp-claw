/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Installer: downloads an .ecapp over https into PSRAM, verifies its signature, asks for
 * confirmation in Telegram, stages it in <apps>/<name>.new/ and has the WASM thread swap it in
 * (cap_wasm_do_install() keeps <name>.old/ until the new version loaded). Runs on the caller's
 * task: the agent for apps_install/apps_remove, a short-lived task for /app commands.
 */
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cJSON.h"
#include "cap_http_rules.h"
#include "cap_wasm_internal.h"
#include "claw_paths.h"
#include "claw_storage_guard.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_URL_MAX       256
#define CAP_WASM_HTTP_MS       30000
#define CAP_WASM_CONFIRM_MS    120000
#define CAP_WASM_JOB_STACK     (12 * 1024)
#define CAP_WASM_OUTPUT_MAX    2048
#define CAP_WASM_MAX_REDIRECTS 5

atomic_flag g_cap_wasm_busy = ATOMIC_FLAG_INIT;

typedef struct {
    uint8_t *buf;         /* with max: collect the body here... */
    size_t max;
    cap_wasm_sink_t sink; /* ...or hand it to sink */
    void *sink_ctx;
    bool sink_failed;
    size_t len;
    bool too_big;
    bool redirect_refused;
    char *location;
    int location_headers; /* Location headers in the current response */
} cap_wasm_dl_t;

static esp_err_t cap_wasm_dl_event(esp_http_client_event_t *evt)
{
    cap_wasm_dl_t *dl = evt->user_data;

    if (evt->event_id == HTTP_EVENT_HEADERS_SENT) {
        free(dl->location);
        dl->location = NULL;
        dl->location_headers = 0;
        return ESP_OK;
    }
    if (evt->event_id == HTTP_EVENT_ON_HEADER && evt->header_key && evt->header_value &&
            strcasecmp(evt->header_key, "Location") == 0) {
        /* esp_http_client concatenates repeated Location headers: refuse those. */
        free(dl->location);
        dl->location = ++dl->location_headers == 1 ? strdup(evt->header_value) : NULL;
        return ESP_OK;
    }
    /* Release downloads redirect to signed CDN URLs: follow https targets only (no auth is sent). */
    if (evt->event_id == HTTP_EVENT_REDIRECT) {
        if (!dl->location || strlen(dl->location) >= CAP_HTTP_REQUEST_REDIRECT_URL_MAX ||
                !cap_http_rules_https_location_ok(dl->location)) {
            dl->redirect_refused = true;
            return ESP_FAIL;
        }
        return esp_http_client_set_redirection(evt->client);
    }
    /* Bodies of redirect responses also arrive here. */
    if (evt->event_id != HTTP_EVENT_ON_DATA || esp_http_client_get_status_code(evt->client) != 200 || dl->too_big ||
            dl->sink_failed) {
        return ESP_OK;
    }
    if (dl->sink) {
        dl->sink_failed = !dl->sink(dl->sink_ctx, evt->data, evt->data_len);
        dl->len += evt->data_len;
        return ESP_OK;
    }
    if ((size_t)evt->data_len > dl->max - dl->len) {
        dl->too_big = true;
        return ESP_OK;
    }
    memcpy(dl->buf + dl->len, evt->data, evt->data_len);
    dl->len += evt->data_len;
    return ESP_OK;
}

/* GET `url` into dl (buffer or sink); ESP_OK on HTTP 200 with the whole body taken. */
static esp_err_t cap_wasm_fetch(const char *url, cap_wasm_dl_t *dl, char *err, size_t err_size)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .event_handler = cap_wasm_dl_event,
        .user_data = dl,
        .timeout_ms = CAP_WASM_HTTP_MS,
        .buffer_size = 4096, /* response headers, incl. a long Location */
        .buffer_size_tx = CAP_HTTP_REQUEST_REDIRECT_URL_MAX + 512, /* request line of the redirect target */
        .crt_bundle_attach = esp_crt_bundle_attach,
        .disable_auto_redirect = true,
        .max_redirection_count = CAP_WASM_MAX_REDIRECTS,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_err_t ret = client ? esp_http_client_perform(client) : ESP_ERR_NO_MEM;
    int status = client ? esp_http_client_get_status_code(client) : 0;

    if (client) {
        esp_http_client_cleanup(client);
    }
    free(dl->location);
    dl->location = NULL;
    /* The query string may carry a token, so it is not logged. */
    ESP_LOGI(TAG, "download %.*s: %s, HTTP %d, %u bytes", (int)strcspn(url, "?#"), url, esp_err_to_name(ret), status,
             (unsigned)dl->len);
    if (ret == ESP_OK && status == 200 && !dl->too_big && !dl->sink_failed && dl->len > 0) {
        return ESP_OK;
    }
    if (dl->too_big) {
        snprintf(err, err_size, "the download is larger than %u KB", (unsigned)(dl->max / 1024));
    } else if (dl->sink_failed) {
        snprintf(err, err_size, "cannot store the download");
    } else if (dl->redirect_refused) {
        snprintf(err, err_size, "redirect refused (HTTP %d to a non-https or overlong URL)", status);
    } else {
        snprintf(err, err_size, "download failed (%s, HTTP %d)", esp_err_to_name(ret), status);
    }
    return ESP_FAIL;
}

uint8_t *cap_wasm_download(const char *url, size_t max, size_t *out_len, char *err, size_t err_size)
{
    cap_wasm_dl_t dl = { .buf = heap_caps_malloc(max + 1, CAP_WASM_PSRAM_CAPS), .max = max };

    if (!dl.buf) {
        snprintf(err, err_size, "out of memory");
        return NULL;
    }
    if (cap_wasm_fetch(url, &dl, err, err_size) != ESP_OK) {
        heap_caps_free(dl.buf);
        return NULL;
    }
    dl.buf[dl.len] = '\0';
    *out_len = dl.len;
    return dl.buf;
}

esp_err_t cap_wasm_stream(const char *url, cap_wasm_sink_t sink, void *ctx, char *err, size_t err_size)
{
    cap_wasm_dl_t dl = { .sink = sink, .sink_ctx = ctx };

    return cap_wasm_fetch(url, &dl, err, err_size);
}

bool cap_wasm_installed_manifest(const char *name, cap_wasm_manifest_t *mf)
{
    char path[96];
    char err[96];
    size_t size = 0;
    char *json;
    bool ok;

    snprintf(path, sizeof(path), "%s/%s/manifest.json", g_cap_wasm_apps_dir, name);
    json = cap_wasm_read_file(path, CAP_WASM_MANIFEST_MAX, &size);
    ok = json && cap_wasm_manifest_parse(json, name, mf, err, sizeof(err));
    heap_caps_free(json);
    return ok;
}

static bool cap_wasm_release_sink(void *ctx, const uint8_t *data, size_t len)
{
    cap_wasm_rel_scan_feed(ctx, (const char *)data, len);
    return true;
}

bool cap_wasm_release_latest(const char *repo, cap_wasm_rel_scan_t *scan, char *err, size_t err_size)
{
    char url[CAP_WASM_GH_REPO_MAX + 48];

    snprintf(url, sizeof(url), "https://api.github.com/repos/%s/releases/latest", repo);
    if (cap_wasm_stream(url, cap_wasm_release_sink, scan, err, err_size) == ESP_OK) {
        return true;
    }
    if (strstr(err, "HTTP 403")) {
        snprintf(err, err_size, "GitHub API rate limit reached (HTTP 403), try again later");
    } else if (strstr(err, "HTTP 404")) {
        snprintf(err, err_size, "github.com/%s has no release (HTTP 404)", repo);
    }
    return false;
}

static size_t cap_wasm_html_escape(char *dst, size_t size, const char *src)
{
    size_t len = 0;

    for (; *src && len + 6 < size; src++) {
        const char *entity = *src == '&' ? "&amp;" : *src == '<' ? "&lt;" : *src == '>' ? "&gt;" : NULL;

        if (entity) {
            len += strlcpy(dst + len, entity, size - len);
        } else {
            dst[len++] = *src;
        }
    }
    dst[len] = '\0';
    return len;
}

/* Shows `html` with a confirm and a cancel button; ESP_OK when confirmed. */
esp_err_t cap_wasm_ask(const char *chat, char *html, size_t html_size, const char *yes_label)
{
#if CONFIG_APP_CLAW_CAP_IM_TG
    const char *const labels[] = { yes_label, "❌ Abbrechen" };
    int choice = -1;
    int64_t message_id = 0;
    size_t len = strlen(html);
    esp_err_t err = cap_im_tg_confirm(chat, html, labels, 2, CAP_WASM_CONFIRM_MS, &choice, &message_id);

    if (err != ESP_OK) {
        return err;
    }
    snprintf(html + len, html_size - len, "\n\n<b>%s</b>",
             choice == 0 ? "✅ bestätigt" : choice < 0 ? "⌛ Zeitüberschreitung" : "❌ abgebrochen");
    cap_im_tg_edit_message(chat, message_id, html);
    return choice == 0 ? ESP_OK : choice < 0 ? ESP_ERR_TIMEOUT : ESP_ERR_INVALID_STATE;
#else
    (void)chat;
    (void)html;
    (void)html_size;
    (void)yes_label;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

static bool cap_wasm_stage_mkdir(const char *path)
{
    bool ok;

    if (claw_storage_begin_write(claw_paths_get(CLAW_PATH_DATA), 0) != ESP_OK) {
        return false;
    }
    ok = mkdir(path, 0775) == 0 || errno == EEXIST;
    claw_storage_end_write();
    return ok;
}

static bool cap_wasm_stage_write(const char *path, const cap_wasm_blob_t *blob)
{
    bool ok;

    if (claw_storage_begin_write(claw_paths_get(CLAW_PATH_DATA), blob->len) != ESP_OK) {
        return false;
    }
    ok = cap_wasm_write_file(path, (const char *)blob->data, blob->len);
    claw_storage_end_write();
    return ok;
}

/* Writes the package entries to <apps>/<name>.new/. */
static bool cap_wasm_stage(const char *name, const cap_wasm_pkg_t *pkg)
{
    const struct {
        const char *file;
        const cap_wasm_blob_t *blob;
    } files[] = {
        {"manifest.json", &pkg->manifest},
        {"app.wasm", &pkg->wasm},
        {"signature.json", &pkg->signature},
    };
    char dir[96];
    char path[128];

    snprintf(dir, sizeof(dir), "%s/%s.new", g_cap_wasm_apps_dir, name);
    if (access(g_cap_wasm_apps_dir, F_OK) != 0) {
        if (!cap_wasm_stage_mkdir(g_cap_wasm_apps_dir)) {
            return false;
        }
    }
    if (!cap_wasm_rmdir(dir) || !cap_wasm_stage_mkdir(dir)) {
        return false;
    }
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, files[i].file);
        if (!cap_wasm_stage_write(path, files[i].blob)) {
            cap_wasm_rmdir(dir);
            return false;
        }
    }
    return true;
}

esp_err_t cap_wasm_install(const char *url, const char *expect_name, bool force, bool confirmed,
                           const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    const char *chat = cap_im_tg_confirm_chat(ctx);
    const size_t html_size = 1536;
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
    char perms[320];
    char err[128];
    char *manifest = NULL;
    char *sig = NULL;
    char *html = NULL;
    uint8_t *buf = NULL;
    size_t len = 0;
    cap_wasm_manifest_t *mf = NULL; /* new and installed manifest, PSRAM: ~2 KB each */
    cap_wasm_manifest_t *old = NULL;
    cap_wasm_pkg_t pkg;
    esp_err_t ret = ESP_FAIL;
    bool installed;
    bool added;
    int cmp = 0;

    if (!chat) {
        snprintf(output, output_size, "Error: installing needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (strncmp(url, "https://", 8) != 0 || strlen(url) >= CAP_WASM_URL_MAX) {
        snprintf(output, output_size, "Error: %s", expect_name && !url[0] ?
                 "no source URL recorded for this app; /app update <name> <https-url>" :
                 "the URL must start with https:// and have at most 255 chars");
        return ESP_ERR_INVALID_ARG;
    }
    if (atomic_flag_test_and_set(&g_cap_wasm_busy)) {
        snprintf(output, output_size, "Error: another app install or firmware update is running, try again later");
        return ESP_ERR_INVALID_STATE;
    }

    buf = cap_wasm_download(url, CAP_WASM_PKG_MAX, &len, err, sizeof(err));
    if (!buf || !cap_wasm_pkg_parse(buf, len, &pkg, err, sizeof(err))) {
        snprintf(output, output_size, "Error: %s", err);
        goto done;
    }
    manifest = heap_caps_calloc(1, pkg.manifest.len + 1, CAP_WASM_PSRAM_CAPS);
    sig = heap_caps_calloc(1, pkg.signature.len + 1, CAP_WASM_PSRAM_CAPS);
    html = heap_caps_malloc(html_size, CAP_WASM_PSRAM_CAPS);
    mf = heap_caps_malloc(2 * sizeof(*mf), CAP_WASM_PSRAM_CAPS);
    old = mf ? mf + 1 : NULL;
    if (!manifest || !sig || !html || !mf) {
        snprintf(output, output_size, "Error: out of memory");
        goto done;
    }
    memcpy(manifest, pkg.manifest.data, pkg.manifest.len);
    memcpy(sig, pkg.signature.data, pkg.signature.len);
    if (!cap_wasm_manifest_parse(manifest, NULL, mf, err, sizeof(err)) || !cap_wasm_api_check(mf, err, sizeof(err)) ||
            !cap_wasm_sig_verify(sig, mf, pkg.manifest.data, pkg.manifest.len, pkg.wasm.data, pkg.wasm.len,
                                 g_cap_wasm_trusted, g_cap_wasm_trusted_count, pkg.format, key_id, err, sizeof(err))) {
        snprintf(output, output_size, "Error: package rejected: %s", err);
        goto done;
    }
    if (!cap_wasm_version_cmp(mf->version, mf->version, &cmp)) {
        snprintf(output, output_size, "Error: version '%s' is not MAJOR.MINOR.PATCH", mf->version);
        goto done;
    }
    if (expect_name && strcmp(expect_name, mf->name) != 0) {
        snprintf(output, output_size, "Error: the package contains app '%s', not '%s'", mf->name, expect_name);
        goto done;
    }
    installed = cap_wasm_installed_manifest(mf->name, old);
    if (installed && cap_wasm_version_cmp(mf->version, old->version, &cmp) && cmp < 0 && !force) {
        snprintf(output, output_size, "Error: %s %s is older than the installed %s; /app install --force <url> "
                 "downgrades", mf->name, mf->version, old->version);
        goto done;
    }

    added = cap_wasm_perms_describe(mf, installed ? old : NULL, perms, sizeof(perms));
    if (installed) {
        len = (size_t)snprintf(html, html_size, "<b>WASM-App aktualisieren?</b>\n<b>%s</b> %s → %s%s\n", mf->name,
                               old->version, mf->version, cmp < 0 ? " ⚠️ Downgrade" : "");
    } else {
        len = (size_t)snprintf(html, html_size, "<b>WASM-App installieren?</b>\n<b>%s</b> %s (neu)\n", mf->name,
                               mf->version);
    }
    len += cap_wasm_html_escape(html + len, html_size - len, mf->description);
    snprintf(html + len, html_size - len, "\nRechte: %s\nLimits: %u KB Speicher, %u ms pro Aufruf\n"
             "Signiert: Schlüssel <code>%s</code>, app.wasm %u Bytes", perms, (unsigned)mf->memory_kb,
             (unsigned)mf->call_timeout_ms, key_id, (unsigned)pkg.wasm.len);
    cap_im_tg_confirm_note(ctx, html, html_size);
    /* An update confirmed in a list (/app update all) is asked again only for new permissions. */
    ret = confirmed && installed && !added && cmp >= 0 ? ESP_OK : cap_wasm_ask(chat, html, html_size, "✅ Installieren");
    if (ret != ESP_OK) {
        snprintf(output, output_size, "Not installed: %s", ret == ESP_ERR_TIMEOUT ? "the confirmation timed out" :
                 ret == ESP_ERR_INVALID_STATE ? "cancelled by the user" : esp_err_to_name(ret));
        goto done;
    }
    if (!cap_wasm_stage(mf->name, &pkg)) {
        snprintf(output, output_size, "Error: cannot write %s/%s.new/ (storage full?)", g_cap_wasm_apps_dir, mf->name);
        ret = ESP_FAIL;
        goto done;
    }
    ESP_LOGI(TAG, "installing %s %s (key %s, was %s)", mf->name, mf->version, key_id, installed ? old->version : "-");
    ret = cap_wasm_admin(CAP_WASM_REQ_INSTALL, mf->name, url, output, output_size);

done:
    heap_caps_free(buf);
    heap_caps_free(manifest);
    heap_caps_free(sig);
    heap_caps_free(html);
    heap_caps_free(mf);
    atomic_flag_clear(&g_cap_wasm_busy);
    return ret;
}

esp_err_t cap_wasm_remove(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    const char *chat = cap_im_tg_confirm_chat(ctx);
    cap_wasm_manifest_t *mf = NULL;
    char html[320];
    esp_err_t ret;

    if (!chat) {
        snprintf(output, output_size, "Error: removing needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX)) {
        snprintf(output, output_size, "Error: invalid app name");
        return ESP_ERR_INVALID_ARG;
    }
    mf = heap_caps_malloc(sizeof(*mf), CAP_WASM_PSRAM_CAPS);
    snprintf(html, sizeof(html), "<b>WASM-App entfernen?</b>\n<b>%s</b> %s\nLöscht die App, ihre gespeicherten Daten "
             "und Einstellungen.", name, mf && cap_wasm_installed_manifest(name, mf) ? mf->version :
             "(ohne gültiges Manifest)");
    heap_caps_free(mf);
    cap_im_tg_confirm_note(ctx, html, sizeof(html));
    ret = cap_wasm_ask(chat, html, sizeof(html), "🗑 Entfernen");
    if (ret != ESP_OK) {
        snprintf(output, output_size, "Not removed: %s", ret == ESP_ERR_TIMEOUT ? "the confirmation timed out" :
                 ret == ESP_ERR_INVALID_STATE ? "cancelled by the user" : esp_err_to_name(ret));
        return ret;
    }
    return cap_wasm_admin(CAP_WASM_REQ_REMOVE, name, NULL, output, output_size);
}

#if CONFIG_APP_CLAW_CAP_IM_TG
typedef struct {
    char command[320];
    char chat_id[32];
} cap_wasm_job_t;

static void cap_wasm_job_task(void *arg)
{
    cap_wasm_job_t *job = arg;
    claw_cap_call_context_t ctx = {
        .channel = "telegram",
        .chat_id = job->chat_id,
        .source_cap = "tg_gateway",
        .caller = CLAW_CAP_CALLER_SYSTEM,
    };
    char *output = heap_caps_malloc(CAP_WASM_OUTPUT_MAX, CAP_WASM_PSRAM_CAPS);
    char verb[16] = "";
    char a[sizeof(job->command)] = "";
    char b[sizeof(job->command)] = "";
    bool force;

    sscanf(job->command, "%15s %319s %319s", verb, a, b);
    force = strcmp(a, "--force") == 0;
    if (!output) {
        ESP_LOGE(TAG, "/app %s: out of memory", verb);
    } else if (strcmp(verb, "fw") == 0) {
        cap_wasm_fw_command(job->command + 2, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "install") == 0) {
        cap_wasm_install(force ? b : a, NULL, force, false, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "updates") == 0) {
        cap_wasm_check_updates(output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "update") == 0 && strcmp(a, "all") == 0) {
        cap_wasm_update_all(&ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "update") == 0 && b[0]) {
        cap_wasm_install(b, a, false, false, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "update") == 0 && a[0]) {
        cap_wasm_update(a, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "remove") == 0 && a[0]) {
        cap_wasm_remove(a, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else {
        snprintf(output, CAP_WASM_OUTPUT_MAX, "Usage: /app install [--force] <https-url> | updates | update <name>|all [url] | "
                 "remove <name>");
    }
    if (output && cap_im_tg_send_text(job->chat_id, output) != ESP_OK) {
        ESP_LOGW(TAG, "failed to send the /app %s result", verb);
    }
    heap_caps_free(output);
    free(job);
    vTaskDeleteWithCaps(NULL);
}
#endif

esp_err_t cap_wasm_start_job(const char *command, const char *chat_id)
{
#if CONFIG_APP_CLAW_CAP_IM_TG
    cap_wasm_job_t *job = calloc(1, sizeof(*job));

    if (!job) {
        return ESP_ERR_NO_MEM;
    }
    strlcpy(job->command, command, sizeof(job->command));
    strlcpy(job->chat_id, chat_id, sizeof(job->chat_id));
    if (xTaskCreateWithCaps(cap_wasm_job_task, "wasm_install", CAP_WASM_JOB_STACK, job, 5, NULL,
                            CAP_WASM_PSRAM_CAPS) != pdPASS) {
        free(job);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
#else
    (void)command;
    (void)chat_id;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}
