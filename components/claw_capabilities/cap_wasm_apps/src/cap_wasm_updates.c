/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Update checks against the latest GitHub release of the firmware and of every app installed
 * from one (https://github.com/<owner>/<repo>/releases/download/...): /app updates, /app update
 * <name>|all and a Telegram notice from a background check: daily at update_check_time (local
 * time), once per boot (after UPD_BOOT_DELAY_US) and when a new chat session starts
 * (cap_wasm_updates_kick). One check at a time; boot and session checks at most once per
 * UPD_THROTTLE_US (GitHub allows 60 unauthenticated requests per hour), and a notice repeats only
 * for new versions (cap_wasm_should_notify). Nothing is installed without a confirmation. One HTTP
 * request at a time, on the caller's task or a short-lived one.
 */
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cJSON.h"
#include "cap_wasm_apps.h"
#include "cap_wasm_internal.h"
#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "sdkconfig.h"
#if CONFIG_APP_CLAW_CAP_IM_TG
#include "cap_im_tg.h"
#endif

static const char *TAG = "cap_wasm_upd";

#define UPD_NVS_NS      "upd"
#define UPD_TICK_US     (30LL * 1000 * 1000)
#define UPD_WINDOW_MIN  5          /* the daily check starts within this many minutes of update_check_time */
#define UPD_BOOT_DELAY_US (120LL * 1000 * 1000)  /* uptime before the boot check: WiFi and Telegram settle */
#define UPD_THROTTLE_US   (3600LL * 1000 * 1000) /* boot and session checks: at most one per hour */
#define UPD_CLOCK_VALID 1767225600 /* 2026-01-01: an earlier clock is not set yet */
#define UPD_TASK_STACK  (12 * 1024)
#define UPD_TEXT_MAX    1024
#define UPD_KEYS_MAX    576        /* "name=version;" per item */

typedef struct {
    char name[CAP_WASM_APP_NAME_MAX + 1]; /* "firmware" for the firmware */
    char installed[CAP_WASM_FW_TEXT_MAX + 1];
    char available[CAP_WASM_FW_TEXT_MAX + 1]; /* latest release, "" when unknown */
    char url[CAP_WASM_REL_URL_MAX];           /* the source URL, then the latest package */
    char err[96];
    bool github;                              /* the source is a GitHub release */
    bool newer;
} upd_item_t;

typedef struct {
    upd_item_t items[1 + CAP_WASM_MAX_APPS];
    size_t count;
} upd_list_t;

typedef struct {
    upd_list_t list;
    char text[UPD_TEXT_MAX];
    char keys[UPD_KEYS_MAX];
    char last[UPD_KEYS_MAX];
    char msg[UPD_TEXT_MAX + 96];
} upd_daily_t;

static int s_check_min = -1; /* update_check_time in minutes after midnight, -1: off */
static int s_last_yday = -1;
static bool s_boot_checked;
static atomic_bool s_running;                    /* a check task is running */
static int64_t s_last_start_us = -UPD_THROTTLE_US; /* uptime of the last check; written with s_running held */

/* Appends to the NUL-terminated `out`; output that does not fit is dropped. */
static void upd_append(char *out, size_t size, const char *fmt, ...)
{
    size_t len = strlen(out);
    va_list args;

    if (len + 1 < size) {
        va_start(args, fmt);
        vsnprintf(out + len, size - len, fmt, args);
        va_end(args);
    }
}

/* Installed apps per index.json (only `only` when set) into items; returns how many. */
static size_t upd_read_index(const char *only, upd_item_t *items, size_t max)
{
    char path[96];
    size_t size = 0;
    size_t count = 0;
    char *json;
    cJSON *root;
    const cJSON *item = NULL;

    snprintf(path, sizeof(path), "%s/index.json", g_cap_wasm_apps_dir);
    json = cap_wasm_read_file(path, 16 * 1024, &size);
    root = json ? cJSON_Parse(json) : NULL;
    heap_caps_free(json);
    cJSON_ArrayForEach(item, cJSON_GetObjectItem(root, "apps")) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(item, "name"));
        const char *version = cJSON_GetStringValue(cJSON_GetObjectItem(item, "version"));
        const char *source = cJSON_GetStringValue(cJSON_GetObjectItem(item, "source"));

        if (count < max && name && (!only || strcmp(name, only) == 0)) {
            memset(&items[count], 0, sizeof(items[count]));
            strlcpy(items[count].name, name, sizeof(items[count].name));
            strlcpy(items[count].installed, version ? version : "", sizeof(items[count].installed));
            strlcpy(items[count].url, source ? source : "", sizeof(items[count].url));
            count++;
        }
    }
    cJSON_Delete(root);
    return count;
}

/* Looks up the latest release when the app came from a GitHub release URL. */
static void upd_lookup_app(upd_item_t *u)
{
    char repo[CAP_WASM_GH_REPO_MAX];
    cap_wasm_rel_app_t pick = { .name = u->name };
    cap_wasm_rel_scan_t scan = { .on_asset = cap_wasm_rel_app_asset, .ctx = &pick };
    int cmp = 0;

    u->github = cap_wasm_gh_release_repo(u->url, repo, sizeof(repo));
    if (!u->github || !cap_wasm_release_latest(repo, &scan, u->err, sizeof(u->err))) {
        return;
    }
    if (!cap_wasm_rel_app_pick(&pick, scan.tag)) {
        snprintf(u->err, sizeof(u->err), "no %s-<version>.ecapp in the latest release", u->name);
    } else if (!cap_wasm_version_cmp(pick.version, u->installed, &cmp)) {
        snprintf(u->err, sizeof(u->err), "cannot compare version '%s' with '%s'", pick.version, u->installed);
    } else {
        strcpy(u->url, pick.url);
        strcpy(u->available, pick.version);
        u->newer = cmp > 0;
    }
}

/* The firmware (when asked for) and every installed app, looked up one after the other. */
static void upd_collect(upd_list_t *list, bool firmware)
{
    list->count = 0;
    if (firmware) {
        upd_item_t *fw = &list->items[list->count++];
        int cmp = 0;

        memset(fw, 0, sizeof(*fw));
        strcpy(fw->name, "firmware");
        strlcpy(fw->installed, esp_app_get_description()->version, sizeof(fw->installed));
        fw->github = true;
        fw->newer = cap_wasm_fw_latest(fw->available, &cmp, fw->err, sizeof(fw->err)) && cmp > 0;
    }
    list->count += upd_read_index(NULL, list->items + list->count, CAP_WASM_MAX_APPS);
    for (size_t i = firmware; i < list->count; i++) {
        upd_lookup_app(&list->items[i]);
    }
}

static void upd_flags(const upd_list_t *list, bool *fw_new, bool *apps_new, bool *failed)
{
    *fw_new = *apps_new = *failed = false;
    for (size_t i = 0; i < list->count; i++) {
        *failed |= list->items[i].err[0] != '\0';
        if (list->items[i].newer) {
            *(strcmp(list->items[i].name, "firmware") == 0 ? fw_new : apps_new) = true;
        }
    }
}

/* Appends one line per item. */
static void upd_describe(const upd_list_t *list, char *out, size_t size)
{
    for (size_t i = 0; i < list->count; i++) {
        const upd_item_t *u = &list->items[i];

        if (u->newer) {
            upd_append(out, size, "\n%s %s → %s", u->name, u->installed, u->available);
        } else if (u->err[0]) {
            upd_append(out, size, "\n%s %s: check failed: %s", u->name, u->installed, u->err);
        } else if (!u->github) {
            upd_append(out, size, "\n%s %s: not installed from a GitHub release", u->name, u->installed);
        } else {
            upd_append(out, size, "\n%s %s ✓", u->name, u->installed);
        }
    }
}

static const char *upd_hint(bool fw_new, bool apps_new)
{
    return fw_new && apps_new ? "/fw update, /app update all" : fw_new ? "/fw update" : "/app update all";
}

esp_err_t cap_wasm_check_updates(char *output, size_t output_size)
{
    upd_list_t *list = heap_caps_calloc(1, sizeof(*list), CAP_WASM_PSRAM_CAPS);
    bool fw_new;
    bool apps_new;
    bool failed;

    if (!list) {
        snprintf(output, output_size, "Error: out of memory");
        return ESP_ERR_NO_MEM;
    }
    upd_collect(list, true);
    upd_flags(list, &fw_new, &apps_new, &failed);
    snprintf(output, output_size, "%s", fw_new || apps_new ? "Updates available:" :
             failed ? "No updates found, but some checks failed:" : "Everything is up to date:");
    upd_describe(list, output, output_size);
    if (fw_new || apps_new) {
        upd_append(output, output_size, "\n%s", upd_hint(fw_new, apps_new));
    }
    ESP_LOGI(TAG, "update check: %s%s", fw_new || apps_new ? "updates available" : "nothing new",
             failed ? ", some lookups failed" : "");
    heap_caps_free(list);
    return ESP_OK;
}

esp_err_t cap_wasm_update(const char *name, const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    upd_item_t u;

    if (!cap_wasm_confirm_chat(ctx)) {
        snprintf(output, output_size, "Error: updating needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (upd_read_index(name, &u, 1) == 0) {
        snprintf(output, output_size, "Error: app '%s' is not installed", name);
        return ESP_ERR_NOT_FOUND;
    }
    upd_lookup_app(&u);
    if (u.err[0]) {
        snprintf(output, output_size, "Error: %s: %s", name, u.err);
        return ESP_FAIL;
    }
    if (u.github && !u.newer) {
        snprintf(output, output_size, "%s %s is up to date (latest release: %s)", name, u.installed, u.available);
        return ESP_OK;
    }
    return cap_wasm_install(u.url, name, false, false, ctx, output, output_size);
}

esp_err_t cap_wasm_update_all(const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    const char *chat = cap_wasm_confirm_chat(ctx);
    const size_t html_size = 1024;
    upd_list_t *list = NULL;
    char *html = NULL;
    esp_err_t ret = ESP_OK;
    bool fw_new;
    bool apps_new;
    bool failed;

    if (!chat) {
        snprintf(output, output_size, "Error: updating needs a confirmation in a Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    list = heap_caps_calloc(1, sizeof(*list), CAP_WASM_PSRAM_CAPS);
    html = heap_caps_malloc(html_size, CAP_WASM_PSRAM_CAPS);
    if (!list || !html) {
        snprintf(output, output_size, "Error: out of memory");
        ret = ESP_ERR_NO_MEM;
        goto done;
    }
    upd_collect(list, false);
    upd_flags(list, &fw_new, &apps_new, &failed);
    if (!apps_new) {
        snprintf(output, output_size, "No app updates to install:");
        upd_describe(list, output, output_size);
        goto done;
    }
    snprintf(html, html_size, "<b>Alle App-Updates installieren?</b>");
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].newer) {
            upd_append(html, html_size, "\n<b>%s</b> %s → %s", list->items[i].name, list->items[i].installed,
                       list->items[i].available);
        }
    }
    upd_append(html, html_size, "\nNeue Rechte werden je App extra bestätigt.");
    ret = cap_wasm_ask(chat, html, html_size, "✅ Alle installieren");
    if (ret != ESP_OK) {
        snprintf(output, output_size, "Not updated: %s", ret == ESP_ERR_TIMEOUT ? "the confirmation timed out" :
                 ret == ESP_ERR_INVALID_STATE ? "cancelled by the user" : esp_err_to_name(ret));
        goto done;
    }
    output[0] = '\0';
    for (size_t i = 0; i < list->count; i++) {
        const upd_item_t *u = &list->items[i];
        size_t len;

        if (!u->newer) {
            continue;
        }
        upd_append(output, output_size, "%s%s: ", output[0] ? "\n" : "", u->name);
        len = strlen(output);
        ret = cap_wasm_install(u->url, u->name, false, true, ctx, output + len, output_size - len);
        if (ret != ESP_OK) {
            upd_append(output, output_size, "\nStopped: the remaining updates were not installed.");
            break;
        }
    }

done:
    heap_caps_free(list);
    heap_caps_free(html);
    return ret;
}

/* ---------- Background check ---------- */

void cap_wasm_apps_set_update_check(const char *hhmm)
{
    unsigned hour;
    unsigned min;

    s_check_min = -1;
    if (!hhmm || !hhmm[0]) {
        return;
    }
    if (sscanf(hhmm, "%2u:%2u", &hour, &min) != 2 || hour > 23 || min > 59 || strlen(hhmm) > 5) {
        ESP_LOGW(TAG, "update_check_time '%s' is not HH:MM; no daily update check", hhmm);
        return;
    }
    s_check_min = (int)(hour * 60 + min);
}

/* arg: the trigger ("daily", "boot" or "session"), for the log. */
static void upd_check_task(void *arg)
{
    upd_daily_t *d = heap_caps_calloc(1, sizeof(*d), CAP_WASM_PSRAM_CAPS);
    int64_t last_at = 0;
    int64_t now = time(NULL);
    nvs_handle_t nvs;
    size_t size;
    bool fw_new;
    bool apps_new;
    bool failed;
    bool notify;
    esp_err_t sent = ESP_FAIL;

    if (!d) {
        ESP_LOGW(TAG, "%s update check: out of memory", (const char *)arg);
        atomic_store(&s_running, false);
        vTaskDeleteWithCaps(NULL);
        return;
    }
    upd_collect(&d->list, true);
    upd_flags(&d->list, &fw_new, &apps_new, &failed);
    for (size_t i = 0; i < d->list.count; i++) {
        const upd_item_t *u = &d->list.items[i];

        if (u->newer) {
            upd_append(d->text, sizeof(d->text), "%s%s %s → %s", d->keys[0] ? ", " : "", u->name, u->installed,
                       u->available);
            upd_append(d->keys, sizeof(d->keys), "%s%s=%s", d->keys[0] ? ";" : "", u->name, u->available);
        }
    }
    if (nvs_open(UPD_NVS_NS, NVS_READONLY, &nvs) == ESP_OK) {
        size = sizeof(d->last);
        if (nvs_get_str(nvs, "notified", d->last, &size) != ESP_OK) {
            d->last[0] = '\0';
        }
        nvs_get_i64(nvs, "notified_at", &last_at);
        nvs_close(nvs);
    }
    notify = cap_wasm_should_notify(d->last, last_at, d->keys, now);
    if (notify) {
        snprintf(d->msg, sizeof(d->msg), "🔔 Updates verfügbar: %s — %s", d->text, upd_hint(fw_new, apps_new));
#if CONFIG_APP_CLAW_CAP_IM_TG
        sent = cap_im_tg_send_text_to_allowed(d->msg);
#endif
    }
    if (sent == ESP_OK && nvs_open(UPD_NVS_NS, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_str(nvs, "notified", d->keys);
        nvs_set_i64(nvs, "notified_at", now);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
    ESP_LOGI(TAG, "%s update check: %s%s%s", (const char *)arg, d->keys[0] ? d->keys : "nothing new",
             !notify ? (d->keys[0] ? " (already announced)" : "") : sent == ESP_OK ? " (announced)" :
             " (announcement failed)", failed ? ", some lookups failed" : "");
    heap_caps_free(d);
    atomic_store(&s_running, false);
    vTaskDeleteWithCaps(NULL);
}

/* Starts a check task unless checks are off, the clock is not set, one is running or (not daily)
 * one started within UPD_THROTTLE_US. */
static void upd_start(const char *why, bool daily)
{
    int64_t now_us = esp_timer_get_time();

    if (s_check_min < 0 || time(NULL) < UPD_CLOCK_VALID || atomic_exchange(&s_running, true)) {
        return;
    }
    if (!daily && now_us - s_last_start_us < UPD_THROTTLE_US) {
        atomic_store(&s_running, false);
        ESP_LOGD(TAG, "%s update check skipped: one ran within the hour", why);
        return;
    }
    s_last_start_us = now_us;
    if (xTaskCreateWithCaps(upd_check_task, "upd_check", UPD_TASK_STACK, (void *)why, 4, NULL,
                            CAP_WASM_PSRAM_CAPS) != pdPASS) {
        atomic_store(&s_running, false);
        ESP_LOGW(TAG, "cannot start the %s update check", why);
    }
}

void cap_wasm_updates_kick(void)
{
    upd_start("session", false);
}

static void upd_tick(void *arg)
{
    time_t now = time(NULL);
    struct tm tm;
    int min;

    (void)arg;
    if (now < UPD_CLOCK_VALID || !localtime_r(&now, &tm)) {
        return;
    }
    if (!s_boot_checked && esp_timer_get_time() >= UPD_BOOT_DELAY_US) {
        s_boot_checked = true;
        upd_start("boot", false);
    }
    min = tm.tm_hour * 60 + tm.tm_min;
    if (min < s_check_min || min >= s_check_min + UPD_WINDOW_MIN || tm.tm_yday == s_last_yday) {
        return;
    }
    s_last_yday = tm.tm_yday;
    upd_start("daily", true);
}

void cap_wasm_updates_start(void)
{
    const esp_timer_create_args_t args = { .callback = upd_tick, .name = "upd_tick" };
    esp_timer_handle_t timer;

    if (s_check_min < 0) {
        ESP_LOGI(TAG, "update checks off");
        return;
    }
    if (esp_timer_create(&args, &timer) != ESP_OK || esp_timer_start_periodic(timer, UPD_TICK_US) != ESP_OK) {
        ESP_LOGE(TAG, "cannot start the daily update check timer");
        return;
    }
    ESP_LOGI(TAG, "update check daily at %02d:%02d local time, at boot and on new sessions", s_check_min / 60,
             s_check_min % 60);
}

/* ---------- Tools ---------- */

esp_err_t cap_wasm_check_updates_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                         char *output, size_t output_size)
{
    const char *chat = cap_wasm_confirm_chat(ctx);
    esp_err_t err;

    (void)input_json;
    /* /updates arrives on the Telegram poll task: the requests run on a job task. */
    if (chat && ctx->caller == CLAW_CAP_CALLER_SYSTEM) {
        err = cap_wasm_start_job("updates", chat);
        snprintf(output, output_size, "%s", err == ESP_OK ? "⏳ Checking for updates…" :
                 "Error: cannot start the update check");
        return err;
    }
    return cap_wasm_check_updates(output, output_size);
}

esp_err_t cap_wasm_update_execute(const char *input_json, const claw_cap_call_context_t *ctx,
                                  char *output, size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    const char *value = cJSON_GetStringValue(cJSON_GetObjectItem(input, "name"));
    char name[CAP_WASM_APP_NAME_MAX + 1];
    bool valid = value && value[0] && strlen(value) < sizeof(name);

    if (valid) {
        strcpy(name, value);
    }
    cJSON_Delete(input);
    if (!valid) {
        snprintf(output, output_size, "Error: name (an installed app, or \"all\") is required");
        return ESP_ERR_INVALID_ARG;
    }
    return strcmp(name, "all") == 0 ? cap_wasm_update_all(ctx, output, output_size) :
           cap_wasm_update(name, ctx, output, output_size);
}
