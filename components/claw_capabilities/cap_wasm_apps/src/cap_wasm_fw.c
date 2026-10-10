/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Firmware updates. The source is a signed ESP-IDF app image (tools/fwsign.py): by default the
 * assets edge_agent.bin and edge_agent.bin.sig.json of the latest GitHub release of
 * esp-claw/esp-claw, or <url> and <url>.sig.json. The signature is checked first, then the image
 * is streamed into the inactive OTA slot and hashed on the fly; it only becomes bootable when
 * size and SHA-256 match the signed ones. After the reboot the new image is in PENDING_VERIFY
 * until WiFi and Telegram work and it has run for a minute; otherwise it marks itself invalid
 * and the bootloader goes back to the previous image. Shares the app installer's lock, trusted
 * keys, download code and Telegram confirmation.
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cap_wasm_internal.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "nvs.h"
#include "sdkconfig.h"
#if CONFIG_APP_CLAW_CAP_IM_TG
#include "cap_im_tg.h"
#endif

static const char *TAG = "cap_wasm_fw";

#define FW_RELEASE_URL     "https://api.github.com/repos/esp-claw/esp-claw/releases/latest"
#define FW_ASSET           "edge_agent.bin"
#define FW_SIG_SUFFIX      ".sig.json"
#define FW_RELEASE_MAX     (128 * 1024)
#define FW_URL_MAX         256
#define FW_NVS_NS          "fw"
#define FW_HEALTH_MIN_S    60   /* must run this long before it counts as good */
#define FW_HEALTH_MAX_S    300  /* WiFi and Telegram must be up by then */
#define FW_REPORT_WAIT_S   600  /* how long the boot report waits for Telegram */
#define FW_REBOOT_DELAY_US (5 * 1000 * 1000)
#define FW_TASK_STACK      (6 * 1024)

typedef struct {
    esp_ota_handle_t ota;
    mbedtls_sha256_context sha;
    uint32_t size;
    uint32_t written;
    int next_pct;
    const char *chat;
    int64_t msg_id;
    const char *version;
} fw_write_t;

static void fw_nvs_get(const char *key, char *out, size_t size)
{
    nvs_handle_t nvs;

    out[0] = '\0';
    if (nvs_open(FW_NVS_NS, NVS_READONLY, &nvs) == ESP_OK) {
        if (nvs_get_str(nvs, key, out, &size) != ESP_OK) {
            out[0] = '\0';
        }
        nvs_close(nvs);
    }
}

/* Sets (value) or erases (NULL) `key`. */
static void fw_nvs_set(const char *key, const char *value)
{
    nvs_handle_t nvs;

    if (nvs_open(FW_NVS_NS, NVS_READWRITE, &nvs) != ESP_OK) {
        return;
    }
    if (value) {
        nvs_set_str(nvs, key, value);
    } else {
        nvs_erase_key(nvs, key);
    }
    nvs_commit(nvs);
    nvs_close(nvs);
}

static void fw_send(const char *chat, const char *text)
{
#if CONFIG_APP_CLAW_CAP_IM_TG
    if (chat[0] && cap_im_tg_send_text(chat, text) != ESP_OK) {
        ESP_LOGW(TAG, "cannot send the firmware report");
    }
#else
    (void)chat;
    (void)text;
#endif
}

/* The slot an update would go to, or NULL when the partition table has only one. */
static const esp_partition_t *fw_next_slot(void)
{
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);

    return next != esp_ota_get_running_partition() ? next : NULL;
}

static esp_err_t fw_status(char *output, size_t output_size)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *next = fw_next_slot();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_app_desc_t other;
    char last[192];
    int len;

    esp_ota_get_state_partition(running, &state);
    fw_nvs_get("last", last, sizeof(last));
    len = snprintf(output, output_size, "Firmware %s %s (IDF %s, built %s %s)\nRunning: %s%s\n", desc->project_name,
                   desc->version, desc->idf_ver, desc->date, desc->time, running->label,
                   state == ESP_OTA_IMG_PENDING_VERIFY ? " (new, health check pending)" : "");
    if (len > 0 && (size_t)len < output_size) {
        if (!next) {
            len += snprintf(output + len, output_size - len, "Other slot: none (no OTA partition table)\n");
        } else if (esp_ota_get_partition_description(next, &other) == ESP_OK) {
            len += snprintf(output + len, output_size - len, "Other slot: %s, %s %s\n", next->label,
                            other.project_name, other.version);
        } else {
            len += snprintf(output + len, output_size - len, "Other slot: %s, empty\n", next->label);
        }
    }
    if (len > 0 && (size_t)len < output_size) {
        snprintf(output + len, output_size - len, "Last update: %s\nSource: latest release of github.com/esp-claw/"
                 "esp-claw (%s + %s%s)", last[0] ? last : "none", FW_ASSET, FW_ASSET, FW_SIG_SUFFIX);
    }
    return ESP_OK;
}

/* Image and signature URLs from `url` (an https .bin) or the latest GitHub release. */
static bool fw_resolve(const char *url, char bin[FW_URL_MAX], char sig[FW_URL_MAX], char *err, size_t err_size)
{
    size_t len = 0;
    char *json;
    cJSON *root;
    const cJSON *asset = NULL;

    if (url && url[0]) {
        if (strncmp(url, "https://", 8) != 0 || strpbrk(url, "?#") ||
                strlen(url) + strlen(FW_SIG_SUFFIX) >= FW_URL_MAX) {
            snprintf(err, err_size, "the URL must be https://.../<image>.bin without a query, at most %d chars",
                     (int)(FW_URL_MAX - strlen(FW_SIG_SUFFIX) - 1));
            return false;
        }
        strcpy(bin, url);
        snprintf(sig, FW_URL_MAX, "%s%s", url, FW_SIG_SUFFIX);
        return true;
    }
    json = (char *)cap_wasm_download(FW_RELEASE_URL, FW_RELEASE_MAX, &len, err, err_size);
    root = json ? cJSON_Parse(json) : NULL;
    heap_caps_free(json);
    bin[0] = sig[0] = '\0';
    cJSON_ArrayForEach(asset, cJSON_GetObjectItem(root, "assets")) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(asset, "name"));
        const char *dl = cJSON_GetStringValue(cJSON_GetObjectItem(asset, "browser_download_url"));

        if (name && dl && strncmp(dl, "https://", 8) == 0 && strlen(dl) < FW_URL_MAX) {
            if (strcmp(name, FW_ASSET) == 0) {
                strcpy(bin, dl);
            } else if (strcmp(name, FW_ASSET FW_SIG_SUFFIX) == 0) {
                strcpy(sig, dl);
            }
        }
    }
    if (json && (!bin[0] || !sig[0])) {
        snprintf(err, err_size, "the latest release has no %s and %s%s assets", FW_ASSET, FW_ASSET, FW_SIG_SUFFIX);
    }
    cJSON_Delete(root);
    return bin[0] && sig[0];
}

/*
 * Resolves the source, fetches and verifies the signature and checks it against this device.
 * `cmp` is the signed version compared to the running one; false with `err` set on any problem.
 */
static bool fw_prepare(const char *url, char bin[FW_URL_MAX], cap_wasm_fw_sig_t *sig, int *cmp,
                       char *err, size_t err_size)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    const esp_partition_t *next = fw_next_slot();
    char sig_url[FW_URL_MAX];
    size_t len = 0;
    char *json;
    bool ok;

    if (!next) {
        snprintf(err, err_size, "this partition table has no second app slot");
        return false;
    }
    if (!fw_resolve(url, bin, sig_url, err, err_size)) {
        return false;
    }
    json = (char *)cap_wasm_download(sig_url, CAP_WASM_SIGNATURE_MAX, &len, err, err_size);
    ok = json && cap_wasm_fw_sig_verify(json, g_cap_wasm_trusted, g_cap_wasm_trusted_count, sig, err, err_size);
    heap_caps_free(json);
    if (!ok) {
        return false;
    }
    if (strcmp(sig->project, desc->project_name) != 0) {
        snprintf(err, err_size, "the image is for project '%s', this device runs '%s'", sig->project, desc->project_name);
        return false;
    }
    if (sig->size > next->size) {
        snprintf(err, err_size, "the image (%" PRIu32 " bytes) does not fit %s (%" PRIu32 " bytes)", sig->size,
                 next->label, next->size);
        return false;
    }
    if (!cap_wasm_version_cmp(sig->version, desc->version, cmp)) {
        *cmp = 0; /* not comparable: treated like a reinstall, needs --force */
    }
    return true;
}

static esp_err_t fw_check(const char *url, char *output, size_t output_size)
{
    const char *running = esp_app_get_description()->version;
    char bin[FW_URL_MAX];
    char err[128];
    cap_wasm_fw_sig_t sig;
    int cmp = 0;

    if (!fw_prepare(url, bin, &sig, &cmp, err, sizeof(err))) {
        snprintf(output, output_size, "Error: %s", err);
        return ESP_FAIL;
    }
    snprintf(output, output_size, "%s %s (%" PRIu32 " KB, signed by key %s): %s", sig.project, sig.version,
             sig.size / 1024, sig.key_id,
             cmp > 0 ? "update available, /fw update installs it" :
             cmp < 0 ? "older than the running firmware" : "same as the running firmware");
    ESP_LOGI(TAG, "check: running %s, offered %s", running, sig.version);
    return ESP_OK;
}

static bool fw_sink(void *ctx, const uint8_t *data, size_t len)
{
    fw_write_t *w = ctx;
    int pct;

    if (len > w->size - w->written || esp_ota_write(w->ota, data, len) != ESP_OK) {
        return false;
    }
    mbedtls_sha256_update(&w->sha, data, len);
    w->written += len;
    pct = (int)((uint64_t)w->written * 100 / w->size);
#if CONFIG_APP_CLAW_CAP_IM_TG
    if (w->msg_id && pct >= w->next_pct && w->next_pct < 100) {
        char text[64];

        snprintf(text, sizeof(text), "⬇️ Firmware %s: %d %%", w->version, pct);
        cap_im_tg_edit_message(w->chat, w->msg_id, text);
        w->next_pct = pct - pct % 25 + 25;
    }
#endif
    return true;
}

static void fw_reboot(void *arg)
{
    (void)arg;
    esp_restart();
}

/* Streams the signed image into the next slot; ESP_OK when it is verified and set to boot. */
static esp_err_t fw_write(const char *bin, const cap_wasm_fw_sig_t *sig, const char *chat, char *err, size_t err_size)
{
    const esp_partition_t *next = fw_next_slot();
    fw_write_t w = { .size = sig->size, .next_pct = 25, .chat = chat, .version = sig->version };
    uint8_t hash[32];
    char hex[CAP_WASM_SHA_HEX_LEN + 1];
    esp_app_desc_t desc;
    esp_err_t ret = esp_ota_begin(next, OTA_WITH_SEQUENTIAL_WRITES, &w.ota);

    if (ret != ESP_OK) {
        snprintf(err, err_size, "cannot start writing %s: %s", next->label, esp_err_to_name(ret));
        return ret;
    }
#if CONFIG_APP_CLAW_CAP_IM_TG
    char text[96];

    snprintf(text, sizeof(text), "⬇️ Firmware %s: 0 %%", sig->version);
    cap_im_tg_send_html(chat, text, &w.msg_id);
#endif
    mbedtls_sha256_init(&w.sha);
    mbedtls_sha256_starts(&w.sha, 0);
    ret = cap_wasm_stream(bin, fw_sink, &w, err, err_size);
    mbedtls_sha256_finish(&w.sha, hash);
    mbedtls_sha256_free(&w.sha);
    for (size_t i = 0; i < sizeof(hash); i++) {
        snprintf(hex + 2 * i, 3, "%02x", hash[i]);
    }
    if (ret == ESP_OK && (w.written != sig->size || strcmp(hex, sig->sha256) != 0)) {
        snprintf(err, err_size, "the image does not match its signature (%" PRIu32 " of %" PRIu32 " bytes, sha256 %.8s)",
                 w.written, sig->size, hex);
        ret = ESP_ERR_INVALID_CRC;
    }
    if (ret != ESP_OK) {
        esp_ota_abort(w.ota);
        return ret;
    }
    ret = esp_ota_end(w.ota);
    if (ret == ESP_OK && (esp_ota_get_partition_description(next, &desc) != ESP_OK ||
                          strcmp(desc.project_name, sig->project) != 0 || strcmp(desc.version, sig->version) != 0)) {
        ret = ESP_ERR_INVALID_VERSION;
    }
    if (ret != ESP_OK) {
        snprintf(err, err_size, "the written image is not valid: %s", esp_err_to_name(ret));
        return ret;
    }
    ret = esp_ota_set_boot_partition(next);
    if (ret != ESP_OK) {
        snprintf(err, err_size, "cannot select %s for boot: %s", next->label, esp_err_to_name(ret));
    }
#if CONFIG_APP_CLAW_CAP_IM_TG
    if (ret == ESP_OK && w.msg_id) {
        snprintf(text, sizeof(text), "✅ Firmware %s geprüft, Neustart…", sig->version);
        cap_im_tg_edit_message(chat, w.msg_id, text);
    }
#endif
    return ret;
}

static esp_err_t fw_update(const char *url, bool force, const claw_cap_call_context_t *ctx,
                           char *output, size_t output_size)
{
    const char *chat = cap_wasm_confirm_chat(ctx);
    const char *running = esp_app_get_description()->version;
    const size_t html_size = 512;
    const esp_timer_create_args_t reboot_args = { .callback = fw_reboot, .name = "fw_reboot" };
    esp_timer_handle_t reboot_timer = NULL;
    char bin[FW_URL_MAX];
    char err[160];
    char last[192];
    char *html = NULL;
    cap_wasm_fw_sig_t sig;
    esp_err_t ret = ESP_FAIL;
    int cmp = 0;

    if (!chat) {
        snprintf(output, output_size, "Error: a firmware update needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (atomic_flag_test_and_set(&g_cap_wasm_busy)) {
        snprintf(output, output_size, "Error: an app install or firmware update is running, try again later");
        return ESP_ERR_INVALID_STATE;
    }
    if (!fw_prepare(url, bin, &sig, &cmp, err, sizeof(err))) {
        snprintf(output, output_size, "Error: %s", err);
        goto done;
    }
    if (cmp <= 0 && !force) {
        snprintf(output, output_size, "Error: %s is %s the running %s; /fw update --force%s%s installs it anyway",
                 sig.version, cmp < 0 ? "older than" : "the same as or not comparable to", running,
                 url && url[0] ? " " : "", url ? url : "");
        goto done;
    }
    html = heap_caps_malloc(html_size, CAP_WASM_PSRAM_CAPS);
    if (!html) {
        snprintf(output, output_size, "Error: out of memory");
        goto done;
    }
    snprintf(html, html_size, "<b>Firmware aktualisieren?</b>\n<b>%s</b> %s → %s%s\n%" PRIu32 " KB nach %s, "
             "signiert: Schlüssel <code>%s</code>\nDas Gerät startet danach neu; scheitert der Start, kehrt es zur "
             "alten Version zurück.", sig.project, running, sig.version, cmp < 0 ? " ⚠️ Downgrade" : "",
             sig.size / 1024, fw_next_slot()->label, sig.key_id);
    ret = cap_wasm_ask(chat, html, html_size, "✅ Aktualisieren");
    if (ret != ESP_OK) {
        snprintf(output, output_size, "Not updated: %s", ret == ESP_ERR_TIMEOUT ? "the confirmation timed out" :
                 ret == ESP_ERR_INVALID_STATE ? "cancelled by the user" : esp_err_to_name(ret));
        goto done;
    }
    ESP_LOGI(TAG, "updating %s -> %s (key %s)", running, sig.version, sig.key_id);
    ret = fw_write(bin, &sig, chat, err, sizeof(err));
    if (ret != ESP_OK) {
        snprintf(last, sizeof(last), "%s -> %s failed: %.90s", running, sig.version, err);
        fw_nvs_set("last", last);
        snprintf(output, output_size, "Error: %s", err);
        goto done;
    }
    /* Read back after the reboot by cap_wasm_fw_boot() of whichever image runs then. */
    fw_nvs_set("chat", chat);
    fw_nvs_set("from", running);
    fw_nvs_set("to", sig.version);
    snprintf(output, output_size, "Firmware %s written and verified; rebooting into it now. It reports back here "
             "after the health check.", sig.version);
    if (esp_timer_create(&reboot_args, &reboot_timer) != ESP_OK ||
            esp_timer_start_once(reboot_timer, FW_REBOOT_DELAY_US) != ESP_OK) {
        esp_restart();
    }

done:
    heap_caps_free(html);
    atomic_flag_clear(&g_cap_wasm_busy);
    return ret;
}

esp_err_t cap_wasm_fw_command(const char *args, const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    char verb[16] = "";
    char a[FW_URL_MAX] = "";
    char b[FW_URL_MAX] = "";
    bool force;

    sscanf(args, "%15s %255s %255s", verb, a, b);
    force = strcmp(a, "--force") == 0;
    if (!verb[0] || strcmp(verb, "status") == 0) {
        return fw_status(output, output_size);
    }
    if (strcmp(verb, "check") == 0) {
        return fw_check(a, output, output_size);
    }
    if (strcmp(verb, "update") == 0) {
        return fw_update(force ? b : a, force, ctx, output, output_size);
    }
    snprintf(output, output_size, "Usage:\n/fw  Firmware status\n/fw check [url]  Look for a newer signed firmware\n"
             "/fw update [--force] [url]  Install it (asks first; --force allows a downgrade or reinstall)\n"
             "url: an https .bin with <url>%s next to it; default: the latest GitHub release", FW_SIG_SUFFIX);
    return ESP_ERR_INVALID_ARG;
}

/* ---------- After the reboot ---------- */

static bool fw_healthy(void)
{
    wifi_ap_record_t ap;

#if CONFIG_APP_CLAW_CAP_IM_TG
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK && cap_im_tg_is_online();
#else
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
#endif
}

static void fw_boot_task(void *arg)
{
    const esp_app_desc_t *desc = esp_app_get_description();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    char chat[32];
    char from[CAP_WASM_FW_TEXT_MAX + 1];
    char to[CAP_WASM_FW_TEXT_MAX + 1];
    char last[192];
    char text[320];

    (void)arg;
    esp_ota_get_state_partition(esp_ota_get_running_partition(), &state);
    fw_nvs_get("chat", chat, sizeof(chat));
    fw_nvs_get("from", from, sizeof(from));
    fw_nvs_get("to", to, sizeof(to));
    fw_nvs_get("last", last, sizeof(last));

    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
        ESP_LOGI(TAG, "new firmware %s: health check (WiFi + Telegram, %d s)", desc->version, FW_HEALTH_MIN_S);
        while (!fw_healthy() || esp_timer_get_time() / 1000000 < FW_HEALTH_MIN_S) {
            if (esp_timer_get_time() / 1000000 >= FW_HEALTH_MAX_S) {
                snprintf(last, sizeof(last), "rolled back from %s: WiFi/Telegram not up within %d s", desc->version,
                         FW_HEALTH_MAX_S);
                fw_nvs_set("last", last);
                ESP_LOGE(TAG, "%s", last);
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
        esp_ota_mark_app_valid_cancel_rollback();
        snprintf(last, sizeof(last), "updated %s -> %s", from[0] ? from : "?", desc->version);
        snprintf(text, sizeof(text), "✅ Firmware aktualisiert auf %s (vorher %s)", desc->version, from[0] ? from : "?");
    } else if (strcmp(desc->version, to) == 0) {
        snprintf(last, sizeof(last), "updated %s -> %s", from[0] ? from : "?", desc->version);
        snprintf(text, sizeof(text), "✅ Firmware aktualisiert auf %s (vorher %s)", desc->version, from[0] ? from : "?");
    } else {
        /* The new image crashed, was reset or failed its health check before marking itself valid. */
        if (strncmp(last, "rolled back from", 16) != 0) {
            snprintf(last, sizeof(last), "rolled back from %s: it crashed or was reset before the health check passed",
                     to);
        }
        snprintf(text, sizeof(text), "↩️ Firmware %s zurückgerollt, läuft wieder %s (%s)", to, desc->version, last);
    }
    ESP_LOGI(TAG, "%s", last);
    fw_nvs_set("last", last);
    fw_nvs_set("chat", NULL);
    fw_nvs_set("from", NULL);
    fw_nvs_set("to", NULL);
#if CONFIG_APP_CLAW_CAP_IM_TG
    for (int s = 0; s < FW_REPORT_WAIT_S && !cap_im_tg_is_online(); s++) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
#endif
    fw_send(chat, text);
    vTaskDeleteWithCaps(NULL);
}

void cap_wasm_fw_boot(void)
{
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    char to[CAP_WASM_FW_TEXT_MAX + 1];

    esp_ota_get_state_partition(esp_ota_get_running_partition(), &state);
    fw_nvs_get("to", to, sizeof(to));
    if ((state == ESP_OTA_IMG_PENDING_VERIFY || to[0]) &&
            xTaskCreateWithCaps(fw_boot_task, "fw_boot", FW_TASK_STACK, NULL, 4, NULL, CAP_WASM_PSRAM_CAPS) != pdPASS) {
        /* Without the task a pending image is never confirmed and rolls back on the next reset. */
        ESP_LOGE(TAG, "cannot start the firmware health check");
    }
}

/* ---------- Tools ---------- */

static void fw_input_str(const char *input_json, const char *key, char *out, size_t size)
{
    cJSON *input = cJSON_Parse(input_json);
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(input, key));

    strlcpy(out, value ? value : "", size);
    cJSON_Delete(input);
}

esp_err_t cap_wasm_fw_command_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                      char *output, size_t output_size)
{
    char command[300] = "fw ";
    char verb[16] = "";
    const char *chat = cap_wasm_confirm_chat(ctx);
    esp_err_t err;

    fw_input_str(input_json, "command", command + 3, sizeof(command) - 3);
    sscanf(command + 3, "%15s", verb);
    if (strcmp(verb, "check") != 0 && strcmp(verb, "update") != 0) {
        return cap_wasm_fw_command(command + 3, ctx, output, output_size);
    }
    /* Network work and the confirmation (answered by the Telegram poll task) run on a job task. */
    err = chat ? cap_wasm_start_job(command, chat) : ESP_ERR_NOT_SUPPORTED;
    snprintf(output, output_size, "%s", err == ESP_OK ? "⏳ Working on it…" :
             chat ? "Error: cannot start the update task" : "Error: needs a Telegram chat");
    return err;
}

esp_err_t cap_wasm_fw_status_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                     char *output, size_t output_size)
{
    (void)input_json;
    (void)ctx;
    return fw_status(output, output_size);
}

esp_err_t cap_wasm_fw_check_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                    char *output, size_t output_size)
{
    char url[FW_URL_MAX];

    (void)ctx;
    fw_input_str(input_json, "url", url, sizeof(url));
    return fw_check(url, output, output_size);
}

esp_err_t cap_wasm_fw_update_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                     char *output, size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    bool force = cJSON_IsTrue(cJSON_GetObjectItem(input, "force"));
    char url[FW_URL_MAX];

    cJSON_Delete(input);
    fw_input_str(input_json, "url", url, sizeof(url));
    return fw_update(url, force, ctx, output, output_size);
}
