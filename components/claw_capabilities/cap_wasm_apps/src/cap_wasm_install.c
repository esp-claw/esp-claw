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
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#if CONFIG_APP_CLAW_CAP_IM_TG
#include "cap_im_tg.h"
#endif

static const char *TAG = "cap_wasm_apps";

#define CAP_WASM_URL_MAX       256
#define CAP_WASM_HTTP_MS       30000
#define CAP_WASM_CONFIRM_MS    120000
#define CAP_WASM_JOB_STACK     (12 * 1024)
#define CAP_WASM_OUTPUT_MAX    1024
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

/* Version from <apps>/<name>/manifest.json into `out` ("" when not installed or unreadable). */
static void cap_wasm_installed_version(const char *name, char out[CAP_WASM_VERSION_MAX + 1])
{
    char path[96];
    char err[96];
    size_t size = 0;
    char *json;
    cap_wasm_manifest_t mf;

    snprintf(path, sizeof(path), "%s/%s/manifest.json", g_cap_wasm_apps_dir, name);
    json = cap_wasm_read_file(path, CAP_WASM_MANIFEST_MAX, &size);
    out[0] = '\0';
    if (json && cap_wasm_manifest_parse(json, name, &mf, err, sizeof(err))) {
        strcpy(out, mf.version);
    }
    heap_caps_free(json);
}

/* Where `name` was installed from, per index.json ("" when unknown). */
static void cap_wasm_source_url(const char *name, char out[CAP_WASM_URL_MAX])
{
    char path[96];
    size_t size = 0;
    char *json;
    cJSON *root;
    const cJSON *item = NULL;

    snprintf(path, sizeof(path), "%s/index.json", g_cap_wasm_apps_dir);
    json = cap_wasm_read_file(path, 16 * 1024, &size);
    root = json ? cJSON_Parse(json) : NULL;
    heap_caps_free(json);
    out[0] = '\0';
    cJSON_ArrayForEach(item, cJSON_GetObjectItem(root, "apps")) {
        const char *item_name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
        const char *source = cJSON_GetStringValue(cJSON_GetObjectItem(item, "source"));

        if (item_name && source && strcmp(item_name, name) == 0) {
            strlcpy(out, source, CAP_WASM_URL_MAX);
        }
    }
    cJSON_Delete(root);
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

static void cap_wasm_describe_perms(const cap_wasm_manifest_t *mf, char *out, size_t size)
{
    static const struct {
        uint32_t perm;
        const char *name;
    } names[] = {
        {CAP_WASM_PERM_LOG, "log"},
        {CAP_WASM_PERM_KV, "kv"},
        {CAP_WASM_PERM_CONFIRM, "confirm"},
        {CAP_WASM_PERM_PING, "ping"},
    };
    size_t len = 0;

    out[0] = '\0';
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if (mf->perms & names[i].perm) {
            len += snprintf(out + len, len < size ? size - len : 0, "%s%s", len ? ", " : "", names[i].name);
        }
    }
    for (uint32_t i = 0; i < mf->http_profile_count; i++) {
        len += snprintf(out + len, len < size ? size - len : 0, "%s%s%s", len ? ", " : "", i ? "" : "http: ",
                        mf->http_profiles[i]);
    }
    if (!len) {
        snprintf(out, size, "keine");
    }
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
    mkdir(g_cap_wasm_apps_dir, 0775);
    if (!cap_wasm_rmdir(dir) || mkdir(dir, 0775) != 0) {
        return false;
    }
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        snprintf(path, sizeof(path), "%s/%s", dir, files[i].file);
        if (!cap_wasm_write_file(path, (const char *)files[i].blob->data, files[i].blob->len)) {
            cap_wasm_rmdir(dir);
            return false;
        }
    }
    return true;
}

esp_err_t cap_wasm_install(const char *url, const char *expect_name, bool force,
                           const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    const char *chat = cap_wasm_confirm_chat(ctx);
    const size_t html_size = 1536;
    char source[CAP_WASM_URL_MAX];
    char installed[CAP_WASM_VERSION_MAX + 1];
    char key_id[CAP_WASM_KEY_ID_LEN + 1];
    char perms[160];
    char err[128];
    char *manifest = NULL;
    char *sig = NULL;
    char *html = NULL;
    uint8_t *buf = NULL;
    size_t len = 0;
    cap_wasm_manifest_t mf;
    cap_wasm_pkg_t pkg;
    esp_err_t ret = ESP_FAIL;
    int cmp = 0;

    if (!chat) {
        snprintf(output, output_size, "Error: installing needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (expect_name && !url[0]) {
        cap_wasm_source_url(expect_name, source);
        url = source;
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
    if (!manifest || !sig || !html) {
        snprintf(output, output_size, "Error: out of memory");
        goto done;
    }
    memcpy(manifest, pkg.manifest.data, pkg.manifest.len);
    memcpy(sig, pkg.signature.data, pkg.signature.len);
    if (!cap_wasm_manifest_parse(manifest, NULL, &mf, err, sizeof(err)) ||
            !cap_wasm_sig_verify(sig, &mf, pkg.manifest.data, pkg.manifest.len, pkg.wasm.data, pkg.wasm.len,
                                 g_cap_wasm_trusted, g_cap_wasm_trusted_count, key_id, err, sizeof(err))) {
        snprintf(output, output_size, "Error: package rejected: %s", err);
        goto done;
    }
    if (!cap_wasm_version_cmp(mf.version, mf.version, &cmp)) {
        snprintf(output, output_size, "Error: version '%s' is not MAJOR.MINOR.PATCH", mf.version);
        goto done;
    }
    if (expect_name && strcmp(expect_name, mf.name) != 0) {
        snprintf(output, output_size, "Error: the package contains app '%s', not '%s'", mf.name, expect_name);
        goto done;
    }
    cap_wasm_installed_version(mf.name, installed);
    if (installed[0] && cap_wasm_version_cmp(mf.version, installed, &cmp) && cmp < 0 && !force) {
        snprintf(output, output_size, "Error: %s %s is older than the installed %s; /app install --force <url> "
                 "downgrades", mf.name, mf.version, installed);
        goto done;
    }

    cap_wasm_describe_perms(&mf, perms, sizeof(perms));
    len = (size_t)snprintf(html, html_size, "<b>WASM-App installieren?</b>\n<b>%s</b> %s (%s%s)%s\n", mf.name,
                           mf.version, installed[0] ? "installiert: " : "neu", installed,
                           installed[0] && cmp < 0 ? " ⚠️ Downgrade" : "");
    len += cap_wasm_html_escape(html + len, html_size - len, mf.description);
    snprintf(html + len, html_size - len, "\nRechte: %s\nLimits: %u KB Speicher, %u ms pro Aufruf\n"
             "Signiert: Schlüssel <code>%s</code>, app.wasm %u Bytes", perms, (unsigned)mf.memory_kb,
             (unsigned)mf.call_timeout_ms, key_id, (unsigned)pkg.wasm.len);
    ret = cap_wasm_ask(chat, html, html_size, "✅ Installieren");
    if (ret != ESP_OK) {
        snprintf(output, output_size, "Not installed: %s", ret == ESP_ERR_TIMEOUT ? "the confirmation timed out" :
                 ret == ESP_ERR_INVALID_STATE ? "cancelled by the user" : esp_err_to_name(ret));
        goto done;
    }
    if (!cap_wasm_stage(mf.name, &pkg)) {
        snprintf(output, output_size, "Error: cannot write %s/%s.new/ (storage full?)", g_cap_wasm_apps_dir, mf.name);
        ret = ESP_FAIL;
        goto done;
    }
    ESP_LOGI(TAG, "installing %s %s (key %s, was %s)", mf.name, mf.version, key_id, installed[0] ? installed : "-");
    ret = cap_wasm_admin(CAP_WASM_REQ_INSTALL, mf.name, url, output, output_size);

done:
    heap_caps_free(buf);
    heap_caps_free(manifest);
    heap_caps_free(sig);
    heap_caps_free(html);
    atomic_flag_clear(&g_cap_wasm_busy);
    return ret;
}

esp_err_t cap_wasm_remove(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    const char *chat = cap_wasm_confirm_chat(ctx);
    char installed[CAP_WASM_VERSION_MAX + 1];
    char html[256];
    esp_err_t ret;

    if (!chat) {
        snprintf(output, output_size, "Error: removing needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!cap_wasm_name_valid(name, strlen(name), CAP_WASM_APP_NAME_MAX)) {
        snprintf(output, output_size, "Error: invalid app name");
        return ESP_ERR_INVALID_ARG;
    }
    cap_wasm_installed_version(name, installed);
    snprintf(html, sizeof(html), "<b>WASM-App entfernen?</b>\n<b>%s</b> %s\nLöscht die App und ihre gespeicherten Daten.",
             name, installed[0] ? installed : "(ohne gültiges Manifest)");
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
        cap_wasm_install(force ? b : a, NULL, force, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "update") == 0 && a[0]) {
        cap_wasm_install(b, a, false, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else if (strcmp(verb, "remove") == 0 && a[0]) {
        cap_wasm_remove(a, &ctx, output, CAP_WASM_OUTPUT_MAX);
    } else {
        snprintf(output, CAP_WASM_OUTPUT_MAX, "Usage: /app install [--force] <https-url> | update <name> [url] | "
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
