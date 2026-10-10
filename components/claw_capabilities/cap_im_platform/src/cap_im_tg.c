/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_im_tg.h"
#include "cap_im_attachment.h"
#include "claw_utils_string.h"

#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "cJSON.h"
#include "claw_core.h"
#include "claw_task.h"
#include "claw_event_publisher.h"
#include "claw_cap.h"
#include "esp_crt_bundle.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#if CONFIG_APP_CLAW_CAP_SKILL_MGR
#include "claw_skill.h"
#endif

static const char *TAG = "cap_im_tg";

#define CAP_IM_TG_API_BASE            "https://api.telegram.org"
#define CAP_IM_TG_HTTP_RESP_INIT      2048
#define CAP_IM_TG_MAX_MSG_LEN         4096
#define CAP_IM_TG_LIST_MAX            (8 * 1024) /* /help, /skills, /tools replies, sent in chunks */
#define CAP_IM_TG_LIST_TAIL           32         /* room kept for "… and N more" */
#define CAP_IM_TG_SUMMARY_MAX         100        /* bytes of a skill summary in /skills */
/* Rich messages allow 32768 characters and 500 blocks; stay well below both. */
#define CAP_IM_TG_RICH_MAX_BYTES      30000
#define CAP_IM_TG_RICH_MAX_LINES      400
#define CAP_IM_TG_POLL_TIMEOUT_S      20
#define CAP_IM_TG_RETRY_DELAY_MS      3000
#define CAP_IM_TG_ATTACHMENT_QUEUE_LEN 8
#define CAP_IM_TG_DEDUP_CACHE_SIZE    64
#define CAP_IM_TG_PATH_BUF_SIZE       256
#define CAP_IM_TG_NAME_BUF_SIZE       96
#define CAP_IM_TG_MULTIPART_BOUNDARY  "----cap_im_tg_boundary"
#define CAP_IM_TG_MEDIA_GROUP_MAX_GROUPS 4
#define CAP_IM_TG_MEDIA_GROUP_MAX_ITEMS  10
#define CAP_IM_TG_MEDIA_GROUP_WINDOW_MS  1500
#define CAP_IM_TG_MEDIA_GROUP_ID_LEN     32
#define CAP_IM_TG_MEDIA_KIND_LEN         16
#define CAP_IM_TG_MEDIA_CAPTION_LEN      256
#define CAP_IM_TG_MAX_ALLOWED_USERS      16
#define CAP_IM_TG_STT_MAX_BYTES          (2 * 1024 * 1024)
#define CAP_IM_TG_VOICE_PREFIX           "[Sprachnachricht]"
#define CAP_IM_TG_CONFIRM_PREFIX         "cf:"
#define CAP_IM_TG_CONFIRM_NONCE_LEN      16
#define CAP_IM_TG_BUSY_LABEL_LEN         128
#define CAP_IM_TG_BUSY_LABEL_MAX         120
#define CAP_IM_TG_DRAFT_INTERVAL_MS      20000
#define CAP_IM_TG_TYPING_INTERVAL_MS     4000
#define CAP_IM_TG_BUSY_EXPIRY_MS         (5 * 60 * 1000)

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} cap_im_tg_http_resp_t;

typedef struct {
    FILE *file;
    size_t bytes_written;
    size_t max_bytes;
    bool limit_hit;
} cap_im_tg_download_t;

typedef struct {
    char *chat_id;
    char *sender_id;
    char *message_id;
    char *attachment_kind;
    char *file_id;
    char *original_filename;
    char *mime;
    char *caption;
    char *content_type;
    char *media_group_id;
} cap_im_tg_attachment_job_t;

typedef struct {
    char path[CAP_IM_TG_PATH_BUF_SIZE];
    char kind[CAP_IM_TG_MEDIA_KIND_LEN];
    char caption[CAP_IM_TG_MEDIA_CAPTION_LEN];
} cap_im_tg_media_item_t;

/* An open album; item_count == 0 marks the slot as free. */
typedef struct {
    char media_group_id[CAP_IM_TG_MEDIA_GROUP_ID_LEN];
    char chat_id[32];
    char sender_id[32];
    char message_id[32];
    size_t item_count;
    int64_t last_seen_ms;
    cap_im_tg_media_item_t items[CAP_IM_TG_MEDIA_GROUP_MAX_ITEMS];
} cap_im_tg_media_group_t;

typedef struct {
    char bot_token[192];
    char attachment_root_dir[128];
    char stt_base_url[320];
    char stt_api_key[320];
    char stt_model[64];
    size_t max_inbound_file_bytes;
    bool enable_inbound_attachments;
    TaskHandle_t poll_task;
    TaskHandle_t attachment_task;
    TaskHandle_t busy_task;
    QueueHandle_t attachment_queue;
    volatile bool stop_requested;
    int64_t next_update_id;
    uint64_t seen_update_keys[CAP_IM_TG_DEDUP_CACHE_SIZE];
    size_t seen_update_idx;
    cap_im_tg_media_group_t media_groups[CAP_IM_TG_MEDIA_GROUP_MAX_GROUPS];
    int64_t allowed_user_ids[CAP_IM_TG_MAX_ALLOWED_USERS];
    size_t allowed_user_count;
} cap_im_tg_state_t;

/* The pending inline-button confirmation; nonce is empty when none is pending or it was answered. */
typedef struct {
    SemaphoreHandle_t lock;
    SemaphoreHandle_t answered;
    char nonce[CAP_IM_TG_CONFIRM_NONCE_LEN + 1];
    char chat_id[32];
    int choice_count;
    int choice;
} cap_im_tg_confirm_t;

static EXT_RAM_BSS_ATTR cap_im_tg_state_t s_tg;
static volatile bool s_tg_online; /* a getUpdates poll succeeded since boot */
static bool s_tg_initialized;
static bool s_tg_rich_unsupported;
static cap_im_tg_confirm_t s_confirm;
static portMUX_TYPE s_confirm_mux = portMUX_INITIALIZER_UNLOCKED;

/* What the agent is doing for chat_id (empty when idle), shown as a draft bubble or typing dots.
 * request_id 0 marks work before the agent request exists (voice transcription). */
typedef struct {
    char chat_id[32];
    char label[CAP_IM_TG_BUSY_LABEL_LEN];
    uint32_t request_id;
    int64_t draft_id;
    int64_t expires_ms;
    int64_t sent_ms;
    bool dirty;
} cap_im_tg_busy_t;

static cap_im_tg_busy_t s_busy;
static portMUX_TYPE s_busy_mux = portMUX_INITIALIZER_UNLOCKED;
static bool s_tg_draft_unsupported;

static void cap_im_tg_init_defaults(void)
{
    if (s_tg_initialized) {
        return;
    }

    s_tg.max_inbound_file_bytes = 2 * 1024 * 1024;
    s_tg.enable_inbound_attachments = false;
    s_tg.next_update_id = 0;
    s_confirm.lock = xSemaphoreCreateMutex();
    s_confirm.answered = xSemaphoreCreateBinary();
    s_tg_initialized = true;
}

static int64_t cap_im_tg_now_ms(void)
{
    return esp_timer_get_time() / 1000LL;
}

static uint64_t cap_im_tg_fnv1a64(const char *text)
{
    uint64_t hash = 1469598103934665603ULL;

    if (!text) {
        return hash;
    }

    while (*text) {
        hash ^= (unsigned char)(*text++);
        hash *= 1099511628211ULL;
    }

    return hash;
}

static bool cap_im_tg_dedup_check_and_record(const char *update_key)
{
    uint64_t key;
    size_t i;

    if (!update_key || !update_key[0]) {
        return false;
    }

    key = cap_im_tg_fnv1a64(update_key);
    for (i = 0; i < CAP_IM_TG_DEDUP_CACHE_SIZE; i++) {
        if (s_tg.seen_update_keys[i] == key) {
            return true;
        }
    }

    s_tg.seen_update_keys[s_tg.seen_update_idx] = key;
    s_tg.seen_update_idx = (s_tg.seen_update_idx + 1) % CAP_IM_TG_DEDUP_CACHE_SIZE;
    return false;
}

static esp_err_t cap_im_tg_http_event_handler(esp_http_client_event_t *event)
{
    cap_im_tg_http_resp_t *resp = (cap_im_tg_http_resp_t *)event->user_data;

    if (!resp || event->event_id != HTTP_EVENT_ON_DATA || event->data_len <= 0) {
        return ESP_OK;
    }

    if (resp->len + (size_t)event->data_len + 1 > resp->cap) {
        char *tmp = NULL;
        size_t new_cap = resp->cap * 2;

        if (new_cap < resp->len + (size_t)event->data_len + 1) {
            new_cap = resp->len + (size_t)event->data_len + 1;
        }

        tmp = realloc(resp->buf, new_cap);
        if (!tmp) {
            return ESP_ERR_NO_MEM;
        }

        resp->buf = tmp;
        resp->cap = new_cap;
    }

    memcpy(resp->buf + resp->len, event->data, event->data_len);
    resp->len += (size_t)event->data_len;
    resp->buf[resp->len] = '\0';
    return ESP_OK;
}

static esp_err_t cap_im_tg_api_call_status(const char *method,
                                           const char *body_json,
                                           char **out_response,
                                           int *out_status)
{
    cap_im_tg_http_resp_t resp = {0};
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    char *url = NULL;
    int needed;
    esp_err_t err;
    int status;

    if (!method || !out_response) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_tg.bot_token[0] == '\0') {
        return ESP_ERR_INVALID_STATE;
    }

    needed = snprintf(NULL, 0, "%s/bot%s/%s", CAP_IM_TG_API_BASE, s_tg.bot_token, method);
    if (needed < 0) {
        return ESP_FAIL;
    }

    url = calloc(1, (size_t)needed + 1);
    resp.buf = calloc(1, CAP_IM_TG_HTTP_RESP_INIT);
    if (!url || !resp.buf) {
        free(url);
        free(resp.buf);
        return ESP_ERR_NO_MEM;
    }

    resp.cap = CAP_IM_TG_HTTP_RESP_INIT;
    snprintf(url, (size_t)needed + 1, "%s/bot%s/%s", CAP_IM_TG_API_BASE, s_tg.bot_token, method);

    config.url = url;
    config.event_handler = cap_im_tg_http_event_handler;
    config.user_data = &resp;
    config.timeout_ms = (CAP_IM_TG_POLL_TIMEOUT_S + 5) * 1000;
    config.buffer_size = 2048;
    config.buffer_size_tx = 2048;
    config.crt_bundle_attach = esp_crt_bundle_attach;
#ifdef CONFIG_HTTP_REUSE_ENABLE
    config.keep_alive_enable = true;
#endif

    client = esp_http_client_init(&config);
    if (!client) {
        free(url);
        free(resp.buf);
        return ESP_FAIL;
    }

    if (body_json) {
        esp_http_client_set_method(client, HTTP_METHOD_POST);
        esp_http_client_set_header(client, "Content-Type", "application/json");
        esp_http_client_set_post_field(client, body_json, strlen(body_json));
    }

    err = esp_http_client_perform(client);
    status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    free(url);
    if (out_status) {
        *out_status = status;
    }

    if (err != ESP_OK) {
        free(resp.buf);
        return err;
    }

    if (status < 200 || status >= 300) {
        ESP_LOGW(TAG, "Telegram API error %d: %s", status, resp.buf ? resp.buf : "");
        free(resp.buf);
        return ESP_FAIL;
    }

    *out_response = resp.buf;
    return ESP_OK;
}

static esp_err_t cap_im_tg_api_call(const char *method,
                                    const char *body_json,
                                    char **out_response)
{
    return cap_im_tg_api_call_status(method, body_json, out_response, NULL);
}

static esp_err_t cap_im_tg_publish_inbound_text(const char *chat_id,
                                                const char *sender_id,
                                                const char *message_id,
                                                const char *content)
{
    if (!content || !content[0]) {
        return ESP_OK;
    }

    return claw_event_router_publish_message("tg_gateway",
                                             "telegram",
                                             chat_id,
                                             content,
                                             sender_id,
                                             message_id);
}

static esp_err_t cap_im_tg_publish_attachment_event(const char *chat_id,
                                                    const char *sender_id,
                                                    const char *message_id,
                                                    const char *content_type,
                                                    const char *payload_json)
{
    claw_event_t event = {0};

    if (!chat_id || !message_id || !content_type || !payload_json) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(event.source_cap, "tg_gateway", sizeof(event.source_cap));
    strlcpy(event.event_type, "attachment_saved", sizeof(event.event_type));
    strlcpy(event.source_channel, "telegram", sizeof(event.source_channel));
    strlcpy(event.chat_id, chat_id, sizeof(event.chat_id));
    if (sender_id && sender_id[0]) {
        strlcpy(event.sender_id, sender_id, sizeof(event.sender_id));
    }
    strlcpy(event.message_id, message_id, sizeof(event.message_id));
    strlcpy(event.content_type, content_type, sizeof(event.content_type));
    event.timestamp_ms = cap_im_tg_now_ms();
    event.session_policy = CLAW_SESSION_POLICY_CHAT;
    snprintf(event.event_id, sizeof(event.event_id), "tg-attach-%" PRId64, event.timestamp_ms);
    event.text = "";
    event.payload_json = (char *)payload_json;
    return claw_event_router_publish(&event);
}

static cap_im_tg_media_group_t *cap_im_tg_media_group_find(const char *media_group_id)
{
    size_t i;

    for (i = 0; i < CAP_IM_TG_MEDIA_GROUP_MAX_GROUPS; i++) {
        cap_im_tg_media_group_t *group = &s_tg.media_groups[i];

        if (group->item_count > 0 && strcmp(group->media_group_id, media_group_id) == 0) {
            return group;
        }
    }

    return NULL;
}

static char *cap_im_tg_media_group_format(const cap_im_tg_media_group_t *group)
{
    const char *caption = "";
    size_t content_len;
    size_t offset;
    size_t i;
    char *content = NULL;

    for (i = 0; i < group->item_count && !caption[0]; i++) {
        caption = group->items[i].caption;
    }
    if (!caption[0]) {
        return NULL;
    }

    content_len = strlen(caption) + 1;
    for (i = 0; i < group->item_count; i++) {
        content_len += strlen(group->items[i].kind) + strlen(group->items[i].path) + 24;
    }
    content = malloc(content_len);
    if (!content) {
        ESP_LOGW(TAG, "Telegram media group text alloc failed message=%s", group->message_id);
        return NULL;
    }

    offset = (size_t)snprintf(content, content_len, "%s", caption);
    for (i = 0; i < group->item_count; i++) {
        offset += (size_t)snprintf(content + offset, content_len - offset,
                                   "\n[Telegram %s saved at: %s]",
                                   group->items[i].kind,
                                   group->items[i].path);
    }
    return content;
}

static void cap_im_tg_media_group_flush(cap_im_tg_media_group_t *group)
{
    char *content = cap_im_tg_media_group_format(group);

    if (content) {
        esp_err_t err = cap_im_tg_publish_inbound_text(group->chat_id,
                                                       group->sender_id,
                                                       group->message_id,
                                                       content);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Telegram media group publish failed: message=%s err=%s",
                     group->message_id, esp_err_to_name(err));
        }
        free(content);
    } else {
        ESP_LOGI(TAG, "Telegram media group without caption not published: message=%s photos=%u",
                 group->message_id, (unsigned int)group->item_count);
    }
    group->item_count = 0;
}

/* Returns a free slot, or flushes the least recently active group to make one. */
static cap_im_tg_media_group_t *cap_im_tg_media_group_take_slot(void)
{
    cap_im_tg_media_group_t *oldest = NULL;
    size_t i;

    for (i = 0; i < CAP_IM_TG_MEDIA_GROUP_MAX_GROUPS; i++) {
        cap_im_tg_media_group_t *group = &s_tg.media_groups[i];

        if (group->item_count == 0) {
            return group;
        }
        if (!oldest || group->last_seen_ms < oldest->last_seen_ms) {
            oldest = group;
        }
    }

    ESP_LOGI(TAG, "Telegram media group buffer full, flushing message=%s", oldest->message_id);
    cap_im_tg_media_group_flush(oldest);
    return oldest;
}

static void cap_im_tg_media_group_flush_expired(void)
{
    int64_t now = cap_im_tg_now_ms();
    size_t i;

    for (i = 0; i < CAP_IM_TG_MEDIA_GROUP_MAX_GROUPS; i++) {
        cap_im_tg_media_group_t *group = &s_tg.media_groups[i];

        if (group->item_count > 0 && now - group->last_seen_ms >= CAP_IM_TG_MEDIA_GROUP_WINDOW_MS) {
            cap_im_tg_media_group_flush(group);
        }
    }
}

/* Returns false when the item cannot be grouped; the caller then publishes it on its own. */
static bool cap_im_tg_media_group_add(const char *media_group_id,
                                      const char *chat_id,
                                      const char *sender_id,
                                      const char *message_id,
                                      const char *attachment_kind,
                                      const char *saved_path,
                                      const char *caption)
{
    cap_im_tg_media_group_t *group = NULL;
    cap_im_tg_media_item_t *item = NULL;

    if (strlen(media_group_id) >= CAP_IM_TG_MEDIA_GROUP_ID_LEN) {
        return false;
    }

    group = cap_im_tg_media_group_find(media_group_id);
    if (group && group->item_count == CAP_IM_TG_MEDIA_GROUP_MAX_ITEMS) {
        cap_im_tg_media_group_flush(group);
        group = NULL;
    }
    if (!group) {
        group = cap_im_tg_media_group_take_slot();
        strlcpy(group->media_group_id, media_group_id, sizeof(group->media_group_id));
        strlcpy(group->chat_id, chat_id, sizeof(group->chat_id));
        strlcpy(group->sender_id, sender_id, sizeof(group->sender_id));
        strlcpy(group->message_id, message_id, sizeof(group->message_id));
    }

    item = &group->items[group->item_count++];
    strlcpy(item->path, saved_path, sizeof(item->path));
    strlcpy(item->kind, attachment_kind, sizeof(item->kind));
    strlcpy(item->caption, caption ? caption : "", sizeof(item->caption));
    group->last_seen_ms = cap_im_tg_now_ms();
    return true;
}

static void cap_im_tg_log_stack_watermark(const char *label)
{
    UBaseType_t words = uxTaskGetStackHighWaterMark(NULL);

    ESP_LOGD(TAG, "%s stack_high_water=%u bytes", label, (unsigned int)(words * sizeof(StackType_t)));
}

static void cap_im_tg_free_attachment_job(cap_im_tg_attachment_job_t *job)
{
    if (!job) {
        return;
    }

    free(job->chat_id);
    free(job->sender_id);
    free(job->message_id);
    free(job->attachment_kind);
    free(job->file_id);
    free(job->original_filename);
    free(job->mime);
    free(job->caption);
    free(job->content_type);
    free(job->media_group_id);
    free(job);
}

static char *cap_im_tg_strdup_or_empty(const char *value)
{
    return strdup(value ? value : "");
}

static cap_im_tg_attachment_job_t *cap_im_tg_make_attachment_job(
    const char *chat_id,
    const char *sender_id,
    const char *message_id,
    const char *attachment_kind,
    const char *file_id,
    const char *original_filename,
    const char *mime,
    const char *caption,
    const char *content_type,
    const char *media_group_id)
{
    cap_im_tg_attachment_job_t *job = calloc(1, sizeof(*job));

    if (!job) {
        return NULL;
    }

    job->chat_id = cap_im_tg_strdup_or_empty(chat_id);
    job->sender_id = cap_im_tg_strdup_or_empty(sender_id);
    job->message_id = cap_im_tg_strdup_or_empty(message_id);
    job->attachment_kind = cap_im_tg_strdup_or_empty(attachment_kind);
    job->file_id = cap_im_tg_strdup_or_empty(file_id);
    job->original_filename = cap_im_tg_strdup_or_empty(original_filename);
    job->mime = cap_im_tg_strdup_or_empty(mime);
    job->caption = cap_im_tg_strdup_or_empty(caption);
    job->content_type = cap_im_tg_strdup_or_empty(content_type);
    job->media_group_id = cap_im_tg_strdup_or_empty(media_group_id);
    if (!job->chat_id || !job->sender_id || !job->message_id || !job->attachment_kind ||
            !job->file_id || !job->original_filename || !job->mime || !job->caption ||
            !job->content_type || !job->media_group_id) {
        cap_im_tg_free_attachment_job(job);
        return NULL;
    }

    return job;
}

static cJSON *cap_im_tg_select_best_photo(cJSON *message_json)
{
    cJSON *photos = cJSON_GetObjectItem(message_json, "photo");
    cJSON *item = NULL;
    cJSON *selected = NULL;

    if (!cJSON_IsArray(photos)) {
        return NULL;
    }

    cJSON_ArrayForEach(item, photos) {
        selected = item;
    }

    return selected;
}

/* Resolves file_id via getFile. *out_size gets Telegram's file_size, or 0 when not reported. */
static char *cap_im_tg_get_file_path(const char *file_id, size_t *out_size)
{
    char method[256];
    char *resp = NULL;
    cJSON *root = NULL;
    cJSON *ok_json;
    cJSON *result_json;
    cJSON *file_path_json;
    cJSON *file_size_json;
    char *copy = NULL;

    *out_size = 0;
    if (!file_id || !file_id[0]) {
        return NULL;
    }

    snprintf(method, sizeof(method), "getFile?file_id=%s", file_id);
    if (cap_im_tg_api_call(method, NULL, &resp) != ESP_OK) {
        return NULL;
    }

    root = cJSON_Parse(resp);
    free(resp);
    if (!root) {
        return NULL;
    }

    ok_json = cJSON_GetObjectItem(root, "ok");
    result_json = cJSON_GetObjectItem(root, "result");
    file_path_json = cJSON_IsObject(result_json) ? cJSON_GetObjectItem(result_json, "file_path") : NULL;
    file_size_json = cJSON_IsObject(result_json) ? cJSON_GetObjectItem(result_json, "file_size") : NULL;
    if (cJSON_IsTrue(ok_json) && cJSON_IsString(file_path_json) && file_path_json->valuestring) {
        copy = strdup(file_path_json->valuestring);
        if (cJSON_IsNumber(file_size_json) && file_size_json->valuedouble > 0) {
            *out_size = (size_t)file_size_json->valuedouble;
        }
    }

    cJSON_Delete(root);
    return copy;
}

static void cap_im_tg_busy_show(const char *chat_id, bool start, uint32_t request_id, const char *label);

/* Publishes a voice/audio message to the agent as text: optional caption line, then the prefixed body. */
static void cap_im_tg_publish_voice_text(const char *chat_id,
                                         const char *sender_id,
                                         const char *message_id,
                                         const char *caption,
                                         const char *body)
{
    bool has_caption = caption && caption[0];
    size_t content_len = (has_caption ? strlen(caption) + 1 : 0) + sizeof(CAP_IM_TG_VOICE_PREFIX) + 1 +
                         strlen(body);
    char *content = malloc(content_len);
    esp_err_t err;

    if (!content) {
        ESP_LOGW(TAG, "Telegram voice text alloc failed: message=%s", message_id);
        return;
    }
    snprintf(content, content_len, "%s%s" CAP_IM_TG_VOICE_PREFIX " %s",
             has_caption ? caption : "", has_caption ? "\n" : "", body);
    err = cap_im_tg_publish_inbound_text(chat_id, sender_id, message_id, content);
    free(content);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Telegram voice text publish failed: message=%s err=%s",
                 message_id, esp_err_to_name(err));
    }
}

/* Transcribes audio and publishes the text (or the failure reason) to the agent. The audio is the
 * file at path, or len bytes of data named filename when data is set. */
static void cap_im_tg_transcribe_and_publish(const char *chat_id,
                                             const char *sender_id,
                                             const char *message_id,
                                             const char *caption,
                                             const char *mime,
                                             const char *path,
                                             const uint8_t *data,
                                             size_t len,
                                             const char *filename)
{
    char reason[192];
    char body[256];
    char *text = NULL;
    esp_err_t err;

    cap_im_tg_busy_show(chat_id, true, 0, "🎙 Transkribiere Sprachnachricht…");
    if (data) {
        err = cap_im_attachment_transcribe_buffer(TAG, s_tg.stt_base_url, s_tg.stt_api_key, s_tg.stt_model,
                                                  data, len, filename, mime, &text, reason, sizeof(reason));
    } else {
        err = cap_im_attachment_transcribe_file(TAG, s_tg.stt_base_url, s_tg.stt_api_key, s_tg.stt_model,
                                                path, mime, &text, reason, sizeof(reason));
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Telegram voice transcription failed: message=%s err=%s reason=%s",
                 message_id, esp_err_to_name(err), reason);
        snprintf(body, sizeof(body), "(konnte nicht transkribiert werden: %s)", reason);
        cap_im_tg_publish_voice_text(chat_id, sender_id, message_id, caption, body);
        return;
    }

    ESP_LOGI(TAG, "Telegram voice transcribed: message=%s chars=%u", message_id, (unsigned int)strlen(text));
    cap_im_tg_publish_voice_text(chat_id, sender_id, message_id, caption,
                                 text[0] ? text : "(leere Transkription)");
    free(text);
}

/* Downloads a voice/audio file into PSRAM and transcribes it from there, so voice notes never touch
 * the flash DATA volume. Returns ESP_ERR_NO_MEM only when the PSRAM buffer could not be allocated,
 * which lets the caller fall back to the flash path; transcription results and failures are
 * published to the agent here. */
static esp_err_t cap_im_tg_transcribe_from_psram(const char *chat_id,
                                                 const char *sender_id,
                                                 const char *message_id,
                                                 const char *original_filename,
                                                 const char *mime,
                                                 const char *caption,
                                                 const char *remote_path,
                                                 size_t expected_bytes)
{
    char *download_url = NULL;
    char filename[CAP_IM_TG_NAME_BUF_SIZE];
    uint8_t *data = NULL;
    size_t len = 0;
    esp_err_t err;

    download_url = malloc(CAP_IM_TG_PATH_BUF_SIZE);
    if (!download_url) {
        return ESP_ERR_NO_MEM;
    }
    snprintf(download_url, CAP_IM_TG_PATH_BUF_SIZE, "%s/file/bot%s/%s",
             CAP_IM_TG_API_BASE, s_tg.bot_token, remote_path);
    err = cap_im_attachment_download_url_to_psram(TAG,
                                                  download_url,
                                                  MIN(s_tg.max_inbound_file_bytes, CAP_IM_TG_STT_MAX_BYTES),
                                                  expected_bytes,
                                                  &data,
                                                  &len);
    free(download_url);
    if (err != ESP_OK) {
        return err;
    }
    ESP_LOGI(TAG, "Telegram audio buffered in PSRAM: message=%s bytes=%u", message_id, (unsigned int)len);

    if (original_filename && original_filename[0]) {
        strlcpy(filename, original_filename, sizeof(filename));
    } else {
        snprintf(filename, sizeof(filename), "audio%s",
                 cap_im_attachment_guess_extension(remote_path, NULL, mime));
    }

    cap_im_tg_transcribe_and_publish(chat_id, sender_id, message_id, caption, mime, NULL, data, len, filename);
    free(data);
    return ESP_OK;
}

static esp_err_t cap_im_tg_save_attachment(const char *chat_id,
                                           const char *sender_id,
                                           const char *message_id,
                                           const char *attachment_kind,
                                           const char *file_id,
                                           const char *original_filename,
                                           const char *mime,
                                           const char *caption,
                                           const char *content_type,
                                           const char *media_group_id)
{
    char saved_dir[CAP_IM_TG_PATH_BUF_SIZE];
    char saved_name[CAP_IM_TG_NAME_BUF_SIZE];
    char saved_path[CAP_IM_TG_PATH_BUF_SIZE];
    char *remote_path = NULL;
    char download_url[CAP_IM_TG_PATH_BUF_SIZE];
    const char *extension = NULL;
    size_t bytes = 0;
    size_t expected_bytes = 0;
    char *payload_json = NULL;
    bool grouped = false;
    esp_err_t err;

    if (!s_tg.enable_inbound_attachments || !s_tg.attachment_root_dir[0] ||
            !chat_id || !message_id || !attachment_kind || !file_id || !content_type) {
        return ESP_ERR_INVALID_STATE;
    }

    remote_path = cap_im_tg_get_file_path(file_id, &expected_bytes);
    if (!remote_path) {
        return ESP_FAIL;
    }

    if (strcmp(content_type, "audio") == 0) {
        err = cap_im_tg_transcribe_from_psram(chat_id, sender_id, message_id, original_filename,
                                              mime, caption, remote_path, expected_bytes);
        if (err != ESP_ERR_NO_MEM) {
            free(remote_path);
            return err;
        }
        ESP_LOGW(TAG, "Telegram audio does not fit in PSRAM, falling back to flash: message=%s", message_id);
    }

    extension = cap_im_attachment_guess_extension(remote_path, original_filename, mime);
    err = cap_im_attachment_build_saved_paths(s_tg.attachment_root_dir,
                                              "telegram",
                                              chat_id,
                                              message_id,
                                              attachment_kind,
                                              extension,
                                              saved_dir,
                                              sizeof(saved_dir),
                                              saved_name,
                                              sizeof(saved_name),
                                              saved_path,
                                              sizeof(saved_path));
    if (err != ESP_OK) {
        free(remote_path);
        return err;
    }

    snprintf(download_url, sizeof(download_url), "%s/file/bot%s/%s",
             CAP_IM_TG_API_BASE, s_tg.bot_token, remote_path);
    err = cap_im_attachment_download_url_to_file(TAG,
                                                 s_tg.attachment_root_dir,
                                                 download_url,
                                                 saved_path,
                                                 strcmp(content_type, "audio") == 0 ?
                                                 MIN(s_tg.max_inbound_file_bytes, CAP_IM_TG_STT_MAX_BYTES) :
                                                 s_tg.max_inbound_file_bytes,
                                                 expected_bytes,
                                                 &bytes);
    if (err != ESP_OK) {
        free(remote_path);
        return err;
    }
    cap_im_attachment_prune_inbox(TAG, s_tg.attachment_root_dir, saved_path);

    grouped = media_group_id && media_group_id[0] &&
              cap_im_tg_media_group_add(media_group_id,
                                        chat_id,
                                        sender_id,
                                        message_id,
                                        attachment_kind,
                                        saved_path,
                                        caption);
    if (strcmp(content_type, "audio") == 0) {
        cap_im_tg_transcribe_and_publish(chat_id, sender_id, message_id, caption, mime, saved_path,
                                         NULL, 0, NULL);
    } else if (!grouped && caption && caption[0]) {
        size_t content_len = strlen(caption) + strlen(saved_path) + 64;
        char *content = malloc(content_len);

        if (content) {
            snprintf(content, content_len, "%s\n[Telegram %s saved at: %s]",
                     caption, attachment_kind, saved_path);
            err = cap_im_tg_publish_inbound_text(chat_id, sender_id, message_id, content);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Telegram attachment caption publish failed: message=%s err=%s",
                         message_id, esp_err_to_name(err));
            }
            free(content);
        }
    }

    payload_json = cap_im_attachment_build_payload_json(
    &(cap_im_attachment_payload_config_t) {
        .platform = "telegram",
        .attachment_kind = attachment_kind,
        .saved_path = saved_path,
        .saved_dir = saved_dir,
        .saved_name = saved_name,
        .original_filename = original_filename,
        .mime = mime,
        .caption = caption,
        .source_key = "platform_file_id",
        .source_value = file_id,
        .size_bytes = bytes,
        .saved_at_ms = cap_im_tg_now_ms(),
    });
    if (!payload_json) {
        free(remote_path);
        ESP_LOGW(TAG, "Telegram attachment payload build failed: message=%s path=%s",
                 message_id, saved_path);
        ESP_LOGI(TAG, "Saved Telegram %s to %s (%u bytes)", attachment_kind, saved_path, (unsigned int)bytes);
        return ESP_OK;
    }

    err = cap_im_tg_publish_attachment_event(chat_id,
                                             sender_id,
                                             message_id,
                                             content_type,
                                             payload_json);
    free(payload_json);
    free(remote_path);
    if (err != ESP_OK) {
        ESP_LOGW(TAG,
                 "Telegram attachment publish event failed: message=%s path=%s err=%s",
                 message_id,
                 saved_path,
                 esp_err_to_name(err));
    }

    ESP_LOGI(TAG, "Saved Telegram %s to %s (%u bytes)", attachment_kind, saved_path, (unsigned int)bytes);
    return ESP_OK;
}

/* Human-readable download failure. ESP_ERR_NO_MEM from the download path means the DATA flash
 * volume is full, not RAM; spelling that out keeps the agent from blaming RAM. */
static const char *cap_im_tg_download_error_reason(esp_err_t err)
{
    switch (err) {
    case ESP_ERR_NO_MEM:
        return "Flash-Datenspeicher (DATA-Partition) voll, auch nach Aufräumen des Anhang-Eingangs";
    case ESP_ERR_INVALID_SIZE:
        return "Datei zu groß";
    default:
        return esp_err_to_name(err);
    }
}

static void cap_im_tg_attachment_task(void *arg)
{
    cap_im_tg_attachment_job_t *job = NULL;

    (void)arg;

    /* Enforce the inbox budget left over from before a reboot. */
    if (s_tg.enable_inbound_attachments) {
        cap_im_attachment_prune_inbox(TAG, s_tg.attachment_root_dir, NULL);
    }

    while (1) {
        cap_im_tg_media_group_flush_expired();

        if (xQueueReceive(s_tg.attachment_queue, &job, pdMS_TO_TICKS(200)) == pdTRUE) {
            if (job) {
                esp_err_t err = cap_im_tg_save_attachment(job->chat_id,
                                                          job->sender_id,
                                                          job->message_id,
                                                          job->attachment_kind,
                                                          job->file_id,
                                                          job->original_filename,
                                                          job->mime,
                                                          job->caption,
                                                          job->content_type,
                                                          job->media_group_id);
                if (err != ESP_OK) {
                    ESP_LOGW(TAG,
                             "Failed to save Telegram %s message=%s err=%s",
                             job->attachment_kind,
                             job->message_id,
                             esp_err_to_name(err));
                    if (strcmp(job->content_type, "audio") == 0) {
                        char body[160];

                        snprintf(body, sizeof(body), "(konnte nicht heruntergeladen werden: %s)",
                                 cap_im_tg_download_error_reason(err));
                        cap_im_tg_publish_voice_text(job->chat_id, job->sender_id, job->message_id,
                                                     job->caption, body);
                    }
                }
                cap_im_tg_free_attachment_job(job);
                cap_im_tg_log_stack_watermark("tg_attachment");
            }
            continue;
        }

        if (s_tg.stop_requested) {
            break;
        }
    }

    s_tg.attachment_task = NULL;
    claw_task_delete(NULL);
}

static void cap_im_tg_queue_attachment(const char *chat_id,
                                       const char *sender_id,
                                       const char *message_id,
                                       const char *attachment_kind,
                                       const char *file_id,
                                       const char *original_filename,
                                       const char *mime,
                                       const char *caption,
                                       const char *content_type,
                                       const char *media_group_id)
{
    cap_im_tg_attachment_job_t *job = NULL;

    if (!s_tg.enable_inbound_attachments || !s_tg.attachment_queue || !file_id || !file_id[0]) {
        return;
    }

    job = cap_im_tg_make_attachment_job(chat_id,
                                        sender_id,
                                        message_id,
                                        attachment_kind,
                                        file_id,
                                        original_filename,
                                        mime,
                                        caption,
                                        content_type,
                                        media_group_id);
    if (!job) {
        ESP_LOGW(TAG, "Telegram attachment queue alloc failed message=%s", message_id);
        return;
    }

    if (xQueueSend(s_tg.attachment_queue, &job, 0) != pdTRUE) {
        ESP_LOGW(TAG,
                 "Telegram attachment queue full message=%s kind=%s",
                 message_id,
                 attachment_kind);
        cap_im_tg_free_attachment_job(job);
        return;
    }
}

static void cap_im_tg_send_typing(const char *chat_id)
{
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err;

    body = cJSON_CreateObject();
    if (!body) {
        return;
    }

    cJSON_AddStringToObject(body, "chat_id", chat_id);
    cJSON_AddStringToObject(body, "action", "typing");
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return;
    }

    /* Typing is cosmetic: a failure must never affect message handling. */
    err = cap_im_tg_api_call("sendChatAction", body_json, &resp);
    free(body_json);
    free(resp);
    if (err != ESP_OK) {
        ESP_LOGD(TAG, "Telegram typing action failed: %s", esp_err_to_name(err));
    }
}

static bool cap_im_tg_user_allowed(int64_t user_id)
{
    for (size_t i = 0; i < s_tg.allowed_user_count; i++) {
        if (s_tg.allowed_user_ids[i] == user_id) {
            return true;
        }
    }
    return false;
}

static void cap_im_tg_answer_callback(const char *query_id, const char *text)
{
    cJSON *body = cJSON_CreateObject();
    char *body_json = NULL;
    char *resp = NULL;

    cJSON_AddStringToObject(body, "callback_query_id", query_id);
    cJSON_AddStringToObject(body, "text", text);
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json || cap_im_tg_api_call("answerCallbackQuery", body_json, &resp) != ESP_OK) {
        ESP_LOGW(TAG, "Telegram answerCallbackQuery failed");
    }
    free(body_json);
    free(resp);
}

/* Inline button press on a cap_im_tg_confirm() prompt: "cf:<nonce>:<button index>". */
static void cap_im_tg_handle_callback_query(cJSON *query_json)
{
    const char *query_id = cJSON_GetStringValue(cJSON_GetObjectItem(query_json, "id"));
    const char *data = cJSON_GetStringValue(cJSON_GetObjectItem(query_json, "data"));
    cJSON *from_id_json = cJSON_GetObjectItem(cJSON_GetObjectItem(query_json, "from"), "id");
    cJSON *chat_id_json = cJSON_GetObjectItem(
                              cJSON_GetObjectItem(cJSON_GetObjectItem(query_json, "message"), "chat"), "id");
    const size_t prefix_len = strlen(CAP_IM_TG_CONFIRM_PREFIX);
    char chat_id[32] = "";
    char decision = '\0';
    bool matched = false;
    bool rejected = false;

    if (!query_id) {
        return;
    }
    if (!cJSON_IsNumber(from_id_json) || !cap_im_tg_user_allowed((int64_t)from_id_json->valuedouble)) {
        ESP_LOGW(TAG, "Telegram callback dropped, sender not allowed: user=%" PRId64,
                 cJSON_IsNumber(from_id_json) ? (int64_t)from_id_json->valuedouble : 0);
        return;
    }
    if (cJSON_IsNumber(chat_id_json)) {
        snprintf(chat_id, sizeof(chat_id), "%" PRId64, (int64_t)chat_id_json->valuedouble);
    }
    if (data && strlen(data) == prefix_len + CAP_IM_TG_CONFIRM_NONCE_LEN + 2 &&
            strncmp(data, CAP_IM_TG_CONFIRM_PREFIX, prefix_len) == 0 &&
            data[prefix_len + CAP_IM_TG_CONFIRM_NONCE_LEN] == ':') {
        decision = data[prefix_len + CAP_IM_TG_CONFIRM_NONCE_LEN + 1];
    }

    if (decision >= '0' && decision <= '9') {
        taskENTER_CRITICAL(&s_confirm_mux);
        if (s_confirm.nonce[0] && decision - '0' < s_confirm.choice_count &&
                strncmp(data + prefix_len, s_confirm.nonce, CAP_IM_TG_CONFIRM_NONCE_LEN) == 0 &&
                strcmp(chat_id, s_confirm.chat_id) == 0) {
            s_confirm.choice = decision - '0';
            s_confirm.nonce[0] = '\0';
            matched = true;
            rejected = s_confirm.choice == s_confirm.choice_count - 1;
        }
        taskEXIT_CRITICAL(&s_confirm_mux);
    }

    if (matched) {
        xSemaphoreGive(s_confirm.answered);
        ESP_LOGI(TAG, "Telegram confirmation button %c by user=%" PRId64 " chat=%s",
                 decision, (int64_t)from_id_json->valuedouble, chat_id);
    }
    cap_im_tg_answer_callback(query_id, !matched ? "Abgelaufen" : rejected ? "Abgebrochen" : "Wird ausgeführt");
}

/* "/<name>" or "/<name>@bot" alone or followed by a space. */
static bool cap_im_tg_is_command(const char *text, const char *command)
{
    size_t len = strlen(command);

    return strncmp(text, command, len) == 0 && (text[len] == '\0' || text[len] == ' ' || text[len] == '@');
}

/* /ssh, /apps and /app are answered here instead of by a router rule so they also work on devices
 * whose router_rules.json was seeded before the commands existed. */
static void cap_im_tg_handle_cap_command(const char *chat_id, const char *text, const char *command,
                                         const char *cap_name)
{
    const size_t output_size = 4096;
    const char *args = text + strlen(command);
    cJSON *input = NULL;
    char *input_json = NULL;
    char *output = NULL;

    if (*args == '@') {
        args += strcspn(args, " ");
    }
    while (*args == ' ') {
        args++;
    }

    input = cJSON_CreateObject();
    cJSON_AddStringToObject(input, "command", args);
    input_json = cJSON_PrintUnformatted(input);
    cJSON_Delete(input);
    output = calloc(1, output_size);
    if (input_json && output) {
        claw_cap_call(cap_name, input_json,
                      &(claw_cap_call_context_t) {
                          .channel = "telegram",
                          .chat_id = chat_id,
                          .source_cap = "tg_gateway",
                          .caller = CLAW_CAP_CALLER_SYSTEM,
                      },
                      output, output_size);
        if (cap_im_tg_send_text(chat_id, output) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to send %s reply", command);
        }
    }
    free(input_json);
    free(output);
}

/* Appends to a list reply; once full, only counts what did not fit. */
typedef struct {
    char *buf;
    size_t size;
    size_t len;
    size_t dropped;
} cap_im_tg_list_t;

static void cap_im_tg_list_add(cap_im_tg_list_t *list, const char *fmt, ...)
{
    va_list ap;
    int n;

    if (list->dropped) {
        list->dropped++;
        return;
    }
    va_start(ap, fmt);
    n = vsnprintf(list->buf + list->len, list->size - list->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= list->size - list->len - CAP_IM_TG_LIST_TAIL) {
        list->buf[list->len] = '\0';
        list->dropped = 1;
        return;
    }
    list->len += (size_t)n;
}

/* Sends the list; cap_im_tg_send_text() splits it into messages within Telegram's limit. */
static void cap_im_tg_list_send(const char *chat_id, cap_im_tg_list_t *list, const char *what)
{
    if (list->dropped) {
        snprintf(list->buf + list->len, list->size - list->len, "\n… and %u more", (unsigned)list->dropped);
    }
    if (cap_im_tg_send_text(chat_id, list->buf) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to send the %s list", what);
    }
}

static bool cap_im_tg_list_init(cap_im_tg_list_t *list)
{
    *list = (cap_im_tg_list_t) {
        .buf = heap_caps_malloc(CAP_IM_TG_LIST_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
        .size = CAP_IM_TG_LIST_MAX,
    };
    if (list->buf) {
        list->buf[0] = '\0';
    }
    return list->buf != NULL;
}

static void cap_im_tg_cmd_help(const char *chat_id, const char *args);
static void cap_im_tg_cmd_skills(const char *chat_id, const char *args);
static void cap_im_tg_cmd_tools(const char *chat_id, const char *args);

/*
 * Every slash command handled here: the source of truth for dispatch, /help and setMyCommands.
 * A command with a cap is offered only while that cap is registered (its capability is enabled)
 * and gets {"command": "<args>"}; the others run locally.
 */
static const struct {
    const char *name;
    const char *description;
    const char *cap;
    void (*handler)(const char *chat_id, const char *args);
} s_tg_commands[] = {
    {"help", "List these commands", NULL, cap_im_tg_cmd_help},
    {"session", "Manage chat sessions (new, list, switch, delete)", "session_command", NULL},
    {"llm", "Configure the LLM model and endpoint", "llm_config_command", NULL},
    {"skills", "List the registered skills", NULL, cap_im_tg_cmd_skills},
    {"tools", "List the tools the LLM can call, by capability", NULL, cap_im_tg_cmd_tools},
    {"ssh", "SSH client (pubkey, allowed, allow, revoke)", "ssh_command", NULL},
    {"apps", "WASM apps (list, enable, disable, load, unload, reload)", "apps_command", NULL},
    {"app", "Install, update (update all, updates) or remove a WASM app", "apps_command", NULL},
    {"updates", "Check for app and firmware updates", "apps_check_updates", NULL},
    {"fw", "Firmware status, check and update", "firmware_command", NULL},
};
#define CAP_IM_TG_COMMAND_COUNT (sizeof(s_tg_commands) / sizeof(s_tg_commands[0]))

static bool cap_im_tg_command_enabled(size_t i)
{
    return !s_tg_commands[i].cap || claw_cap_find(s_tg_commands[i].cap) != NULL;
}

/* Bit i set when s_tg_commands[i] is offered. */
static uint32_t cap_im_tg_command_mask(void)
{
    uint32_t mask = 0;

    for (size_t i = 0; i < CAP_IM_TG_COMMAND_COUNT; i++) {
        mask |= cap_im_tg_command_enabled(i) ? 1u << i : 0;
    }
    return mask;
}

static void cap_im_tg_cmd_help(const char *chat_id, const char *args)
{
    cap_im_tg_list_t list;

    (void)args;
    if (!cap_im_tg_list_init(&list)) {
        return;
    }
    cap_im_tg_list_add(&list, "Commands:");
    for (size_t i = 0; i < CAP_IM_TG_COMMAND_COUNT; i++) {
        if (cap_im_tg_command_enabled(i)) {
            cap_im_tg_list_add(&list, "\n/%s — %s", s_tg_commands[i].name, s_tg_commands[i].description);
        }
    }
    cap_im_tg_list_add(&list, "\nAnything else goes to the assistant.");
    cap_im_tg_list_send(chat_id, &list, "command");
    free(list.buf);
}

#if CONFIG_APP_CLAW_CAP_SKILL_MGR
static esp_err_t cap_im_tg_add_skill(const claw_skill_catalog_entry_t *entry, void *user_ctx)
{
    cap_im_tg_list_t *list = user_ctx;
    const char *summary = entry->summary ? entry->summary : "";
    size_t len = claw_utils_utf8_prefix_len(summary, CAP_IM_TG_SUMMARY_MAX);

    cap_im_tg_list_add(list, "\n`%s` %s — %.*s%s", entry->id,
                       entry->manage_mode == CLAW_SKILL_MANAGE_MODE_READONLY ? "(readonly)" : "(runtime)",
                       (int)len, summary, summary[len] ? "…" : "");
    return ESP_OK;
}
#endif

static void cap_im_tg_cmd_skills(const char *chat_id, const char *args)
{
    cap_im_tg_list_t list;

    (void)args;
    if (!cap_im_tg_list_init(&list)) {
        return;
    }
    cap_im_tg_list_add(&list, "Skills:");
#if CONFIG_APP_CLAW_CAP_SKILL_MGR
    if (claw_skill_foreach_catalog_entry(cap_im_tg_add_skill, &list) != ESP_OK) {
        cap_im_tg_list_add(&list, "\n(the skill registry is not ready)");
    }
#else
    cap_im_tg_list_add(&list, "\n(skills are not enabled in this firmware)");
#endif
    cap_im_tg_list_send(chat_id, &list, "skill");
    free(list.buf);
}

/* The WASM app tools with their app and state, from apps_status (cap_wasm_apps). */
static void cap_im_tg_add_wasm_tools(cap_im_tg_list_t *list)
{
    const size_t size = 4096;
    char *status = malloc(size);
    cJSON *apps = NULL;
    const cJSON *app = NULL;

    if (status && claw_cap_call("apps_status", "{}", &(claw_cap_call_context_t) {
                .channel = "telegram",
                .source_cap = "tg_gateway",
                .caller = CLAW_CAP_CALLER_SYSTEM,
            }, status, size) == ESP_OK) {
        apps = cJSON_Parse(status);
    }
    free(status);
    cJSON_ArrayForEach(app, apps) {
        const cJSON *tool = NULL;
        bool first = true;

        cap_im_tg_list_add(list, "\nWASM app `%s` (%s, %s):",
                           cJSON_GetStringValue(cJSON_GetObjectItem(app, "name")) ?: "?",
                           cJSON_GetStringValue(cJSON_GetObjectItem(app, "state")) ?: "?",
                           cJSON_IsTrue(cJSON_GetObjectItem(app, "loaded")) ? "loaded" : "unloaded");
        cJSON_ArrayForEach(tool, cJSON_GetObjectItem(app, "tools")) {
            cap_im_tg_list_add(list, "%s `%s`", first ? "" : ",", cJSON_GetStringValue(tool) ?: "?");
            first = false;
        }
        if (first) {
            cap_im_tg_list_add(list, " no tools");
        }
    }
    cJSON_Delete(apps);
}

static void cap_im_tg_cmd_tools(const char *chat_id, const char *args)
{
    claw_cap_group_list_t groups = claw_cap_list_groups();
    cap_im_tg_list_t list;

    (void)args;
    if (!cap_im_tg_list_init(&list)) {
        return;
    }
    cap_im_tg_list_add(&list, "Tools the LLM can call, by capability:");
    for (size_t g = 0; g < groups.count; g++) {
        claw_cap_list_t caps = claw_cap_list();
        bool first = true;

        /* App tools are listed per app below. */
        if (strcmp(groups.items[g].group_id, "cap_wasm_apps") == 0) {
            continue;
        }
        for (size_t i = 0; i < caps.count; i++) {
            claw_cap_descriptor_info_t info;

            if (!(caps.items[i].cap_flags & CLAW_CAP_FLAG_CALLABLE_BY_LLM) ||
                    claw_cap_get_descriptor_state(caps.items[i].name, &info) != ESP_OK || !info.group_id ||
                    strcmp(info.group_id, groups.items[g].group_id) != 0) {
                continue;
            }
            cap_im_tg_list_add(&list, first ? "\n%s: `%s`" : ", `%s`", first ? groups.items[g].group_id : caps.items[i].name,
                               caps.items[i].name);
            first = false;
        }
    }
    if (claw_cap_find("apps_status")) {
        cap_im_tg_add_wasm_tools(&list);
    }
    cap_im_tg_list_send(chat_id, &list, "tool");
    free(list.buf);
}

/* Runs `text` when it is one of s_tg_commands (and enabled); false otherwise. */
static bool cap_im_tg_dispatch_command(const char *chat_id, const char *text)
{
    char command[24];

    for (size_t i = 0; i < CAP_IM_TG_COMMAND_COUNT; i++) {
        snprintf(command, sizeof(command), "/%s", s_tg_commands[i].name);
        if (!cap_im_tg_is_command(text, command) || !cap_im_tg_command_enabled(i)) {
            continue;
        }
        if (s_tg_commands[i].handler) {
            const char *args = text + strlen(command);

            args += *args == '@' ? strcspn(args, " ") : 0;
            s_tg_commands[i].handler(chat_id, args + strspn(args, " "));
        } else {
            cap_im_tg_handle_cap_command(chat_id, text, command, s_tg_commands[i].cap);
        }
        return true;
    }
    return false;
}

static void cap_im_tg_handle_update(cJSON *update_json)
{
    cJSON *update_id_json;
    cJSON *callback_query_json;
    cJSON *message_json;
    cJSON *chat_json;
    cJSON *chat_id_json;
    cJSON *from_json;
    cJSON *from_id_json;
    cJSON *message_id_json;
    cJSON *text_json;
    cJSON *document_json;
    cJSON *photo_json;
    cJSON *voice_json;
    bool is_voice;
    const char *caption = NULL;
    const char *media_group_id = NULL;
    char update_key[32];
    char chat_id[32];
    char sender_id[32];
    char message_id[32];
    int64_t update_id;

    if (!cJSON_IsObject(update_json)) {
        return;
    }

    update_id_json = cJSON_GetObjectItem(update_json, "update_id");
    if (!cJSON_IsNumber(update_id_json)) {
        return;
    }

    update_id = (int64_t)update_id_json->valuedouble;
    if (update_id >= s_tg.next_update_id) {
        s_tg.next_update_id = update_id + 1;
    }

    snprintf(update_key, sizeof(update_key), "%" PRId64, update_id);
    if (cap_im_tg_dedup_check_and_record(update_key)) {
        return;
    }

    callback_query_json = cJSON_GetObjectItem(update_json, "callback_query");
    if (cJSON_IsObject(callback_query_json)) {
        cap_im_tg_handle_callback_query(callback_query_json);
        return;
    }
    message_json = cJSON_GetObjectItem(update_json, "message");
    if (!cJSON_IsObject(message_json)) {
        return;
    }

    chat_json = cJSON_GetObjectItem(message_json, "chat");
    from_json = cJSON_GetObjectItem(message_json, "from");
    message_id_json = cJSON_GetObjectItem(message_json, "message_id");
    if (!cJSON_IsObject(chat_json) || !cJSON_IsNumber(message_id_json)) {
        return;
    }

    chat_id_json = cJSON_GetObjectItem(chat_json, "id");
    from_id_json = cJSON_IsObject(from_json) ? cJSON_GetObjectItem(from_json, "id") : NULL;
    if (!cJSON_IsNumber(chat_id_json)) {
        return;
    }

    snprintf(chat_id, sizeof(chat_id), "%" PRId64, (int64_t)chat_id_json->valuedouble);
    if (cJSON_IsNumber(from_id_json)) {
        snprintf(sender_id, sizeof(sender_id), "%" PRId64, (int64_t)from_id_json->valuedouble);
    } else {
        sender_id[0] = '\0';
    }
    /* Gate before any download, typing indicator or publish. */
    if (!cJSON_IsNumber(from_id_json) ||
            !cap_im_tg_user_allowed((int64_t)from_id_json->valuedouble)) {
        ESP_LOGW(TAG, "Telegram update dropped, sender not allowed: user=%s chat=%s",
                 sender_id[0] ? sender_id : "(none)", chat_id);
        return;
    }
    snprintf(message_id, sizeof(message_id), "%" PRId64, (int64_t)message_id_json->valuedouble);

    caption = cJSON_GetStringValue(cJSON_GetObjectItem(message_json, "caption"));
    media_group_id = cJSON_GetStringValue(cJSON_GetObjectItem(message_json, "media_group_id"));
    photo_json = cap_im_tg_select_best_photo(message_json);
    if (s_tg.enable_inbound_attachments && photo_json) {
        const char *file_id = cJSON_GetStringValue(cJSON_GetObjectItem(photo_json, "file_id"));

        ESP_LOGI(TAG, "Telegram photo message=%s chat=%s", message_id, chat_id);

        if (file_id && file_id[0]) {
            cap_im_tg_queue_attachment(chat_id,
                                       sender_id,
                                       message_id,
                                       "photo",
                                       file_id,
                                       "photo.jpg",
                                       "image/jpeg",
                                       caption,
                                       "image",
                                       media_group_id);
        }
    }

    document_json = cJSON_GetObjectItem(message_json, "document");
    if (s_tg.enable_inbound_attachments && cJSON_IsObject(document_json)) {
        const char *file_id = cJSON_GetStringValue(cJSON_GetObjectItem(document_json, "file_id"));
        const char *file_name = cJSON_GetStringValue(cJSON_GetObjectItem(document_json, "file_name"));
        const char *mime = cJSON_GetStringValue(cJSON_GetObjectItem(document_json, "mime_type"));

        ESP_LOGI(TAG,
                 "Telegram document message=%s chat=%s filename=%s",
                 message_id,
                 chat_id,
                 file_name ? file_name : "");

        if (file_id && file_id[0]) {
            cap_im_tg_queue_attachment(chat_id,
                                       sender_id,
                                       message_id,
                                       "document",
                                       file_id,
                                       file_name,
                                       mime,
                                       caption,
                                       "file",
                                       media_group_id);
        }
    }

    voice_json = cJSON_GetObjectItem(message_json, "voice");
    is_voice = cJSON_IsObject(voice_json);
    if (!is_voice) {
        voice_json = cJSON_GetObjectItem(message_json, "audio");
    }
    if (s_tg.enable_inbound_attachments && cJSON_IsObject(voice_json)) {
        const char *file_id = cJSON_GetStringValue(cJSON_GetObjectItem(voice_json, "file_id"));
        const char *file_name = cJSON_GetStringValue(cJSON_GetObjectItem(voice_json, "file_name"));
        const char *mime = cJSON_GetStringValue(cJSON_GetObjectItem(voice_json, "mime_type"));
        cJSON *file_size_json = cJSON_GetObjectItem(voice_json, "file_size");

        ESP_LOGI(TAG, "Telegram %s message=%s chat=%s", is_voice ? "voice" : "audio", message_id, chat_id);

        if (!s_tg.stt_api_key[0]) {
            cap_im_tg_publish_voice_text(chat_id, sender_id, message_id, caption,
                                         "Sprachnachrichten sind nicht konfiguriert (stt_api_key fehlt)");
        } else if (cJSON_IsNumber(file_size_json) && file_size_json->valuedouble > CAP_IM_TG_STT_MAX_BYTES) {
            cap_im_tg_publish_voice_text(chat_id, sender_id, message_id, caption,
                                         "(zu groß für die Transkription, maximal 2 MB)");
        } else if (file_id && file_id[0]) {
            /* Telegram voice is OGG/Opus stored as .oga; STT APIs accept it only as .ogg. */
            cap_im_tg_queue_attachment(chat_id,
                                       sender_id,
                                       message_id,
                                       is_voice ? "voice" : "audio",
                                       file_id,
                                       is_voice ? "voice.ogg" : file_name,
                                       is_voice ? "audio/ogg" : mime,
                                       caption,
                                       "audio",
                                       NULL);
        }
    }

    text_json = cJSON_GetObjectItem(message_json, "text");
    if (cJSON_IsString(text_json) && text_json->valuestring &&
            cap_im_tg_dispatch_command(chat_id, text_json->valuestring)) {
        return;
    }
    if (cJSON_IsString(text_json) && text_json->valuestring && text_json->valuestring[0]) {
        if (cap_im_tg_publish_inbound_text(chat_id,
                                           sender_id,
                                           message_id,
                                           text_json->valuestring) == ESP_OK) {
            ESP_LOGI(TAG, "Telegram inbound %s: %.48s%s",
                     chat_id,
                     text_json->valuestring,
                     strlen(text_json->valuestring) > 48 ? "..." : "");
        } else {
            ESP_LOGW(TAG, "Failed to publish Telegram inbound message");
        }
    }
}

static esp_err_t cap_im_tg_poll_once(void)
{
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    cJSON *root = NULL;
    cJSON *ok_json;
    cJSON *result_json;
    esp_err_t err;
    int i;

    body = cJSON_CreateObject();
    if (!body) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddNumberToObject(body, "timeout", CAP_IM_TG_POLL_TIMEOUT_S);
    cJSON_AddItemToObject(body, "allowed_updates",
                          cJSON_CreateStringArray((const char *const[]) { "message", "callback_query" }, 2));
    if (s_tg.next_update_id > 0) {
        cJSON_AddNumberToObject(body, "offset", (double)s_tg.next_update_id);
    }

    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return ESP_ERR_NO_MEM;
    }

    err = cap_im_tg_api_call("getUpdates", body_json, &resp);
    free(body_json);
    if (err != ESP_OK) {
        return err;
    }

    root = cJSON_Parse(resp);
    free(resp);
    if (!root) {
        return ESP_FAIL;
    }

    ok_json = cJSON_GetObjectItem(root, "ok");
    result_json = cJSON_GetObjectItem(root, "result");
    if (!cJSON_IsTrue(ok_json) || !cJSON_IsArray(result_json)) {
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    for (i = 0; i < cJSON_GetArraySize(result_json); i++) {
        cap_im_tg_handle_update(cJSON_GetArrayItem(result_json, i));
    }

    cJSON_Delete(root);
    return ESP_OK;
}

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
} cap_im_tg_html_buf_t;

static bool cap_im_tg_html_put(cap_im_tg_html_buf_t *out, const char *text, size_t len)
{
    if (out->len + len + 1 > out->cap) {
        size_t new_cap = out->cap * 2;
        char *tmp = NULL;

        while (new_cap < out->len + len + 1) {
            new_cap *= 2;
        }

        tmp = realloc(out->buf, new_cap);
        if (!tmp) {
            return false;
        }

        out->buf = tmp;
        out->cap = new_cap;
    }

    memcpy(out->buf + out->len, text, len);
    out->len += len;
    out->buf[out->len] = '\0';
    return true;
}

static bool cap_im_tg_html_put_escaped(cap_im_tg_html_buf_t *out, const char *text, size_t len, bool quote)
{
    size_t i;

    for (i = 0; i < len; i++) {
        const char *entity = NULL;

        switch (text[i]) {
        case '&':
            entity = "&amp;";
            break;
        case '<':
            entity = "&lt;";
            break;
        case '>':
            entity = "&gt;";
            break;
        case '"':
            entity = quote ? "&quot;" : NULL;
            break;
        default:
            break;
        }

        if (entity ? !cap_im_tg_html_put(out, entity, strlen(entity))
                   : !cap_im_tg_html_put(out, text + i, 1)) {
            return false;
        }
    }
    return true;
}

/* First occurrence of `c` in [from, end), or NULL. */
static const char *cap_im_tg_md_find_char(const char *from, const char *end, char c)
{
    return from < end ? memchr(from, c, (size_t)(end - from)) : NULL;
}

/* First occurrence of the two-character marker `c c` in [from, end), or NULL. */
static const char *cap_im_tg_md_find_pair(const char *from, const char *end, char c)
{
    const char *p;

    for (p = from; p + 1 < end; p++) {
        if (p[0] == c && p[1] == c) {
            return p;
        }
    }
    return NULL;
}

/* Converts inline Markdown in [line, end). Inline spans never nest, so the output tags always balance. */
static bool cap_im_tg_md_inline(cap_im_tg_html_buf_t *out, const char *line, const char *end)
{
    const char *p = line;

    while (p < end) {
        const char *q = NULL;

        if (p[0] == '`') {
            q = cap_im_tg_md_find_char(p + 1, end, '`');
            if (q && q > p + 1) {
                if (!cap_im_tg_html_put(out, "<code>", 6) ||
                    !cap_im_tg_html_put_escaped(out, p + 1, (size_t)(q - p - 1), false) ||
                    !cap_im_tg_html_put(out, "</code>", 7)) {
                    return false;
                }
                p = q + 1;
                continue;
            }
        } else if (p + 2 < end && p[0] == '*' && p[1] == '*' && p[2] != ' ') {
            q = cap_im_tg_md_find_pair(p + 3, end, '*');
            if (q && q[-1] != ' ') {
                if (!cap_im_tg_html_put(out, "<b>", 3) ||
                    !cap_im_tg_html_put_escaped(out, p + 2, (size_t)(q - p - 2), false) ||
                    !cap_im_tg_html_put(out, "</b>", 4)) {
                    return false;
                }
                p = q + 2;
                continue;
            }
        } else if (p + 1 < end && (p[0] == '*' || p[0] == '_') && p[1] != ' ' && p[1] != '*' &&
                   (p[0] == '*' || p == line || !isalnum((unsigned char)p[-1]))) {
            /* Closer: not after a space, not part of a "**" or "__" run, and for '_' not followed by a word char. */
            for (q = p + 2; q < end; q++) {
                if (q[0] == p[0] && q[-1] != ' ' && q[-1] != p[0] && (q + 1 == end || q[1] != p[0]) &&
                    (p[0] == '*' || q + 1 == end || !isalnum((unsigned char)q[1]))) {
                    break;
                }
            }
            if (q < end) {
                if (!cap_im_tg_html_put(out, "<i>", 3) ||
                    !cap_im_tg_html_put_escaped(out, p + 1, (size_t)(q - p - 1), false) ||
                    !cap_im_tg_html_put(out, "</i>", 4)) {
                    return false;
                }
                p = q + 1;
                continue;
            }
        } else if (p[0] == '[') {
            q = cap_im_tg_md_find_char(p + 1, end, ']');
            if (q && q > p + 1 && q + 1 < end && q[1] == '(') {
                const char *r = cap_im_tg_md_find_char(q + 2, end, ')');

                if (r && r > q + 2) {
                    if (!cap_im_tg_html_put(out, "<a href=\"", 9) ||
                        !cap_im_tg_html_put_escaped(out, q + 2, (size_t)(r - q - 2), true) ||
                        !cap_im_tg_html_put(out, "\">", 2) ||
                        !cap_im_tg_html_put_escaped(out, p + 1, (size_t)(q - p - 1), false) ||
                        !cap_im_tg_html_put(out, "</a>", 4)) {
                        return false;
                    }
                    p = r + 1;
                    continue;
                }
            }
        }

        if (!cap_im_tg_html_put_escaped(out, p, 1, false)) {
            return false;
        }
        p++;
    }
    return true;
}

/* Drops the newline that ends the last code line, then closes the <pre> block. */
static bool cap_im_tg_html_close_pre(cap_im_tg_html_buf_t *out, const char *nl)
{
    if (out->len > 0 && out->buf[out->len - 1] == '\n') {
        out->len--;
        out->buf[out->len] = '\0';
    }
    return cap_im_tg_html_put(out, "</pre>", 6) && cap_im_tg_html_put(out, nl, strlen(nl));
}

/* Converts LLM Markdown to Telegram HTML. Returns a heap string the caller frees, or NULL on OOM. */
static char *cap_im_tg_markdown_to_html(const char *md)
{
    cap_im_tg_html_buf_t out = {0};
    const char *line = md;
    bool in_fence = false;
    bool in_table = false;
    bool ok = true;

    out.cap = 256;
    out.buf = malloc(out.cap);
    if (!out.buf) {
        return NULL;
    }
    out.buf[0] = '\0';

    while (ok && *line) {
        const char *eol = strchr(line, '\n');
        const char *end = eol ? eol : line + strlen(line);
        const char *next = eol ? eol + 1 : end;
        const char *nl = eol ? "\n" : "";
        bool is_fence = strncmp(line, "```", 3) == 0;
        size_t hashes = 0;

        if (in_fence) {
            if (is_fence) {
                in_fence = false;
                ok = cap_im_tg_html_close_pre(&out, nl);
            } else {
                ok = cap_im_tg_html_put_escaped(&out, line, (size_t)(end - line), false) &&
                     cap_im_tg_html_put(&out, nl, strlen(nl));
            }
        } else if (is_fence) {
            /* The language tag on the opening fence is ignored. */
            if (in_table) {
                in_table = false;
                ok = cap_im_tg_html_close_pre(&out, "\n");
            }
            in_fence = true;
            ok = ok && cap_im_tg_html_put(&out, "<pre>", 5);
        } else if (line[0] == '|') {
            if (!in_table) {
                in_table = true;
                ok = cap_im_tg_html_put(&out, "<pre>", 5);
            }
            ok = ok && cap_im_tg_html_put_escaped(&out, line, (size_t)(end - line), false) &&
                 cap_im_tg_html_put(&out, nl, strlen(nl));
        } else {
            if (in_table) {
                in_table = false;
                ok = cap_im_tg_html_close_pre(&out, "\n");
            }

            while (line + hashes < end && line[hashes] == '#' && hashes < 6) {
                hashes++;
            }
            if (hashes > 0 && line + hashes < end && line[hashes] == ' ') {
                const char *text = line + hashes + 1;

                ok = ok && cap_im_tg_html_put(&out, "<b>", 3) &&
                     cap_im_tg_html_put_escaped(&out, text, (size_t)(end - text), false) &&
                     cap_im_tg_html_put(&out, "</b>", 4);
            } else {
                ok = ok && cap_im_tg_md_inline(&out, line, end);
            }
            ok = ok && cap_im_tg_html_put(&out, nl, strlen(nl));
        }

        line = next;
    }

    if (ok && in_fence) {
        ok = cap_im_tg_html_close_pre(&out, "");
    } else if (ok && in_table) {
        ok = cap_im_tg_html_close_pre(&out, "");
    }

    if (!ok) {
        free(out.buf);
        return NULL;
    }
    return out.buf;
}

static esp_err_t cap_im_tg_send_message_body(const char *chat_id, const char *text, const char *parse_mode)
{
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err;

    body = cJSON_CreateObject();
    if (!body) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(body, "chat_id", chat_id);
    cJSON_AddStringToObject(body, "text", text);
    if (parse_mode) {
        cJSON_AddStringToObject(body, "parse_mode", parse_mode);
    }
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return ESP_ERR_NO_MEM;
    }

    err = cap_im_tg_api_call("sendMessage", body_json, &resp);
    free(body_json);
    free(resp);
    return err;
}

static esp_err_t cap_im_tg_send_text_chunk(const char *chat_id, const char *message)
{
    char *html = cap_im_tg_markdown_to_html(message);
    esp_err_t err = ESP_ERR_NO_MEM;

    if (html) {
        err = cap_im_tg_send_message_body(chat_id, html, "HTML");
    }
    /* Retry once as plain text only when Telegram rejects the HTML (ESP_FAIL = non-2xx).
     * Transport errors are not retried: Telegram may already have accepted the message. */
    if (!html || err == ESP_FAIL) {
        err = cap_im_tg_send_message_body(chat_id, message, NULL);
    }
    free(html);
    return err;
}

static esp_err_t cap_im_tg_send_rich_chunk(const char *chat_id, const char *markdown, int *out_status)
{
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err;

    body = cJSON_CreateObject();
    if (!body) {
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddStringToObject(body, "chat_id", chat_id);
    cJSON_AddStringToObject(cJSON_AddObjectToObject(body, "rich_message"), "markdown", markdown);
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return ESP_ERR_NO_MEM;
    }

    err = cap_im_tg_api_call_status("sendRichMessage", body_json, &resp, out_status);
    free(body_json);
    free(resp);
    return err;
}

/* GFM joins single newlines into one paragraph: end every non-blank line that is followed by
 * another line with two spaces (hard break), except inside ```/~~~ fences and on table rows.
 * Trailing spaces at the end of a block are ignored, so this leaves no artifacts. */
static char *cap_im_tg_md_hard_breaks(const char *text)
{
    const char *line = text;
    const char *p;
    size_t lines = 1;
    size_t off = 0;
    char fence = 0;
    char *out;

    for (p = text; *p; p++) {
        lines += *p == '\n';
    }
    out = malloc((size_t)(p - text) + 2 * lines + 1);
    if (!out) {
        return NULL;
    }

    while (*line) {
        const char *nl = strchr(line, '\n');
        size_t line_len = nl ? (size_t)(nl - line) + 1 : strlen(line);

        p = line + strspn(line, " ");
        memcpy(out + off, line, line_len);
        off += line_len;
        if ((*p == '`' || *p == '~') && p[1] == *p && p[2] == *p) {
            if (!fence) {
                fence = *p;
            } else if (*p == fence) {
                fence = 0;
            }
        } else if (!fence && nl && nl[1] && p < nl && *p != '|') {
            memcpy(out + off - 1, "  \n", 3);
            off += 2;
        }
        line += line_len;
    }
    out[off] = '\0';
    return out;
}

/* Length of the next rich chunk: all of it if it fits, else the last paragraph break (or line
 * break) outside a ``` fence before the limits, else any line break, else a UTF-8 safe cut. */
static size_t cap_im_tg_rich_chunk_len(const char *text, size_t len)
{
    size_t i;
    size_t lines = 0;
    size_t para = 0;
    size_t line = 0;
    size_t any = 0;
    bool fence = false;

    for (i = 0; i < len && i < CAP_IM_TG_RICH_MAX_BYTES; i++) {
        if ((i == 0 || text[i - 1] == '\n') && strncmp(text + i + strspn(text + i, " "), "```", 3) == 0) {
            fence = !fence;
        }
        if (text[i] != '\n') {
            continue;
        }
        if (++lines > CAP_IM_TG_RICH_MAX_LINES) {
            break;
        }
        any = i + 1;
        if (!fence) {
            line = i + 1;
            if (i > 0 && text[i - 1] == '\n') {
                para = i + 1;
            }
        }
    }
    if (i == len) {
        return len;
    }
    if (para > i / 2) {
        return para;
    }
    return line ? line : any ? any : claw_utils_utf8_prefix_len(text, CAP_IM_TG_RICH_MAX_BYTES);
}

static const char *cap_im_tg_basename(const char *path)
{
    const char *slash = NULL;

    if (!path || !path[0]) {
        return "";
    }

    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* The plain-text draft label for a tool call, cut UTF-8 safe to CAP_IM_TG_BUSY_LABEL_MAX bytes. */
static void cap_im_tg_busy_tool_label(const char *tool, const char *args_json, char *out, size_t out_size)
{
    cJSON *args = args_json ? cJSON_Parse(args_json) : NULL;
    const char *path = cJSON_GetStringValue(cJSON_GetObjectItem(args, "path"));
    const char *arg = NULL;
    const char *host = NULL;
    char buf[256];
    size_t len;

    if (strcmp(tool, "web_search") == 0) {
        arg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "query"));
        snprintf(buf, sizeof(buf), "🔍 Websuche: „%s“", arg ? arg : "");
    } else if (strcmp(tool, "http_request") == 0) {
        arg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "url"));
        arg = arg ? (strstr(arg, "://") ? strstr(arg, "://") + 3 : arg) : "";
        snprintf(buf, sizeof(buf), "🌐 Rufe %.*s ab", (int)strcspn(arg, "/?#"), arg);
    } else if (strcmp(tool, "ssh_exec") == 0) {
        arg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "command"));
        host = cJSON_GetStringValue(cJSON_GetObjectItem(args, "host"));
        snprintf(buf, sizeof(buf), "🖥 SSH auf %s: %s", host ? host : "", arg ? arg : "");
    } else if (strcmp(tool, "inspect_image") == 0) {
        strlcpy(buf, "🖼 Analysiere Bild…", sizeof(buf));
    } else if (strncmp(tool, "lua_run_script", 14) == 0) {
        snprintf(buf, sizeof(buf), "⚙️ Lua: %s", cap_im_tg_basename(path));
    } else if (strcmp(tool, "activate_skill") == 0) {
        arg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "skill_id"));
        snprintf(buf, sizeof(buf), "📚 Skill: %s", arg ? arg : "");
    } else if (strcmp(tool, "wol_wake") == 0) {
        arg = cJSON_GetStringValue(cJSON_GetObjectItem(args, "target"));
        snprintf(buf, sizeof(buf), "⏰ Wecke %s", arg ? arg : "");
    } else if (strcmp(tool, "write_file") == 0 || strcmp(tool, "read_file") == 0) {
        snprintf(buf, sizeof(buf), "📄 %s", cap_im_tg_basename(path));
    } else if (strcmp(tool, "spawn_agent") == 0) {
        strlcpy(buf, "🤖 Starte Subagent", sizeof(buf));
    } else {
        snprintf(buf, sizeof(buf), "🛠 %s", tool);
    }
    cJSON_Delete(args);

    len = claw_utils_utf8_prefix_len(buf, CAP_IM_TG_BUSY_LABEL_MAX);
    snprintf(out, out_size, "%.*s%s", (int)len, buf, buf[len] ? "…" : "");
}

static void cap_im_tg_busy_show(const char *chat_id, bool start, uint32_t request_id, const char *label)
{
    bool notify = false;
    bool idle;
    bool same_chat;

    taskENTER_CRITICAL(&s_busy_mux);
    idle = !s_busy.chat_id[0] || cap_im_tg_now_ms() >= s_busy.expires_ms;
    same_chat = !idle && strcmp(s_busy.chat_id, chat_id) == 0;
    /* A start never takes over from a running request; an update only touches the busy chat. */
    if (start ? (idle || s_busy.request_id == 0) : same_chat) {
        if (start) {
            /* Keep the transcription draft id so Telegram animates into the request's draft. */
            if (!same_chat || s_busy.request_id != 0 || request_id == 0) {
                s_busy.draft_id = (int64_t)(esp_random() & 0x7fffffff) | 1;
            }
            s_busy.request_id = request_id;
            strlcpy(s_busy.chat_id, chat_id, sizeof(s_busy.chat_id));
        }
        strlcpy(s_busy.label, label, sizeof(s_busy.label));
        s_busy.expires_ms = cap_im_tg_now_ms() + CAP_IM_TG_BUSY_EXPIRY_MS;
        s_busy.dirty = true;
        notify = true;
    }
    taskEXIT_CRITICAL(&s_busy_mux);
    if (notify && s_tg.busy_task) {
        xTaskNotifyGive(s_tg.busy_task);
    }
}

/* claw_core progress observer: runs on the agent task, so it only updates s_busy. */
static void cap_im_tg_busy_progress(claw_core_progress_event_t event,
                                    const claw_core_request_t *request,
                                    const char *tool_name,
                                    const char *args_json)
{
    bool targeted = request->target_channel && request->target_channel[0];
    const char *channel = targeted ? request->target_channel : request->source_channel;
    const char *chat_id = targeted ? request->target_chat_id : request->source_chat_id;
    char label[CAP_IM_TG_BUSY_LABEL_LEN];

    if (!channel || strcmp(channel, "telegram") != 0 || !chat_id || !chat_id[0]) {
        return;
    }
    if (event == CLAW_CORE_PROGRESS_REQUEST_END) {
        taskENTER_CRITICAL(&s_busy_mux);
        if (s_busy.request_id == request->request_id) {
            s_busy.chat_id[0] = '\0';
        }
        taskEXIT_CRITICAL(&s_busy_mux);
        return;
    }
    if (event == CLAW_CORE_PROGRESS_TOOL_CALL && tool_name) {
        cap_im_tg_busy_tool_label(tool_name, args_json, label, sizeof(label));
    } else {
        strlcpy(label, "💭 Denke nach…", sizeof(label));
    }
    cap_im_tg_busy_show(chat_id, event == CLAW_CORE_PROGRESS_REQUEST_START, request->request_id, label);
}

/* sendRichMessageDraft works in private chats only; the first rejection (other than rate
 * limiting) switches to typing dots. */
static void cap_im_tg_send_busy(const char *chat_id, int64_t draft_id, const char *label)
{
    cap_im_tg_html_buf_t html = {.buf = malloc(256), .cap = 256};
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err = ESP_ERR_NO_MEM;
    int status = 0;

    if (!s_tg_draft_unsupported && html.buf &&
            cap_im_tg_html_put(&html, "<tg-thinking>", strlen("<tg-thinking>")) &&
            cap_im_tg_html_put_escaped(&html, label, strlen(label), false) &&
            cap_im_tg_html_put(&html, "</tg-thinking>", strlen("</tg-thinking>")) &&
            (body = cJSON_CreateObject()) != NULL) {
        cJSON_AddNumberToObject(body, "chat_id", strtod(chat_id, NULL));
        cJSON_AddNumberToObject(body, "draft_id", (double)draft_id);
        cJSON_AddStringToObject(cJSON_AddObjectToObject(body, "rich_message"), "html", html.buf);
        body_json = cJSON_PrintUnformatted(body);
        cJSON_Delete(body);
        if (body_json) {
            err = cap_im_tg_api_call_status("sendRichMessageDraft", body_json, &resp, &status);
        }
        free(body_json);
        free(resp);
        if (err == ESP_FAIL && status != 429) {
            s_tg_draft_unsupported = true;
            ESP_LOGI(TAG, "sendRichMessageDraft rejected, using typing dots until reboot");
        }
    }
    free(html.buf);
    if (s_tg_draft_unsupported) {
        cap_im_tg_send_typing(chat_id);
    }
}

static void cap_im_tg_busy_task(void *arg)
{
    char chat_id[sizeof(s_busy.chat_id)];
    char label[CAP_IM_TG_BUSY_LABEL_LEN];
    int64_t draft_id = 0;

    (void)arg;

    while (!s_tg.stop_requested) {
        int64_t now;
        bool confirm_pending;
        bool due = false;

        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
        taskENTER_CRITICAL(&s_confirm_mux);
        confirm_pending = s_confirm.nonce[0] != '\0';
        taskEXIT_CRITICAL(&s_confirm_mux);

        now = cap_im_tg_now_ms();
        taskENTER_CRITICAL(&s_busy_mux);
        if (s_busy.chat_id[0] && now >= s_busy.expires_ms) {
            s_busy.chat_id[0] = '\0';
        }
        if (s_busy.chat_id[0] && confirm_pending) {
            /* Sending the prompt removed the draft: show it again right after the answer. */
            s_busy.dirty = true;
        } else if (s_busy.chat_id[0] &&
                   (s_busy.dirty || now - s_busy.sent_ms >= (s_tg_draft_unsupported ?
                                                             CAP_IM_TG_TYPING_INTERVAL_MS :
                                                             CAP_IM_TG_DRAFT_INTERVAL_MS))) {
            strlcpy(chat_id, s_busy.chat_id, sizeof(chat_id));
            strlcpy(label, s_busy.label, sizeof(label));
            draft_id = s_busy.draft_id;
            s_busy.sent_ms = now;
            s_busy.dirty = false;
            due = true;
        }
        taskEXIT_CRITICAL(&s_busy_mux);

        if (due) {
            cap_im_tg_send_busy(chat_id, draft_id, label);
        }
    }

    s_tg.busy_task = NULL;
    claw_task_delete(NULL);
}

static const char *cap_im_tg_guess_mime_type(const char *path, bool is_image)
{
    const char *ext = NULL;

    if (!path) {
        return is_image ? "image/jpeg" : "application/octet-stream";
    }

    ext = strrchr(path, '.');
    if (!ext) {
        return is_image ? "image/jpeg" : "application/octet-stream";
    }

    if (strcasecmp(ext, ".png") == 0) {
        return "image/png";
    }
    if (strcasecmp(ext, ".gif") == 0) {
        return "image/gif";
    }
    if (strcasecmp(ext, ".webp") == 0) {
        return "image/webp";
    }
    if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) {
        return "image/jpeg";
    }
    if (strcasecmp(ext, ".pdf") == 0) {
        return "application/pdf";
    }
    if (strcasecmp(ext, ".txt") == 0) {
        return "text/plain";
    }
    if (strcasecmp(ext, ".json") == 0) {
        return "application/json";
    }

    return is_image ? "image/jpeg" : "application/octet-stream";
}

static esp_err_t cap_im_tg_http_client_write_all(esp_http_client_handle_t client,
                                                 const char *data,
                                                 size_t len)
{
    size_t total = 0;

    if (!client || (!data && len > 0)) {
        return ESP_ERR_INVALID_ARG;
    }

    while (total < len) {
        int written = esp_http_client_write(client, data + total, (int)(len - total));

        if (written <= 0) {
            return ESP_FAIL;
        }

        total += (size_t)written;
    }

    return ESP_OK;
}

static esp_err_t cap_im_tg_stream_file_to_http_client(esp_http_client_handle_t client, FILE *file)
{
    char buf[1024];

    if (!client || !file) {
        return ESP_ERR_INVALID_ARG;
    }

    while (!feof(file)) {
        size_t nread = fread(buf, 1, sizeof(buf), file);

        if (nread > 0) {
            esp_err_t err = cap_im_tg_http_client_write_all(client, buf, nread);
            if (err != ESP_OK) {
                return err;
            }
        }

        if (ferror(file)) {
            return ESP_FAIL;
        }
    }

    return ESP_OK;
}

static esp_err_t cap_im_tg_send_multipart_file(const char *method,
                                               const char *field_name,
                                               const char *chat_id,
                                               const char *path,
                                               const char *caption,
                                               bool is_image)
{
    struct stat st;
    FILE *file = NULL;
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    cap_im_tg_http_resp_t resp = {0};
    char *url = NULL;
    const char *mime = NULL;
    const char *file_name = NULL;
    char content_type[128];
    char part_chat[256];
    char part_caption[1024];
    char part_file[512];
    char closing[64];
    size_t content_length;
    int needed;
    int status;
    int part_chat_len;
    int part_caption_len = 0;
    int part_file_len;
    int closing_len;
    esp_err_t err = ESP_FAIL;

    if (!method || !field_name || !chat_id || !chat_id[0] || !path || !path[0]) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_tg.bot_token[0] == '\0') {
        return ESP_ERR_INVALID_STATE;
    }
    if (stat(path, &st) != 0) {
        return errno == ENOENT ? ESP_ERR_NOT_FOUND : ESP_FAIL;
    }
    if (!S_ISREG(st.st_mode)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (st.st_size <= 0) {
        return ESP_ERR_INVALID_SIZE;
    }

    needed = snprintf(NULL, 0, "%s/bot%s/%s", CAP_IM_TG_API_BASE, s_tg.bot_token, method);
    if (needed < 0) {
        return ESP_FAIL;
    }

    url = calloc(1, (size_t)needed + 1);
    resp.buf = calloc(1, CAP_IM_TG_HTTP_RESP_INIT);
    if (!url || !resp.buf) {
        free(url);
        free(resp.buf);
        return ESP_ERR_NO_MEM;
    }
    resp.cap = CAP_IM_TG_HTTP_RESP_INIT;
    snprintf(url, (size_t)needed + 1, "%s/bot%s/%s", CAP_IM_TG_API_BASE, s_tg.bot_token, method);

    mime = cap_im_tg_guess_mime_type(path, is_image);
    file_name = cap_im_tg_basename(path);

    part_chat_len = snprintf(part_chat, sizeof(part_chat),
                             "--" CAP_IM_TG_MULTIPART_BOUNDARY "\r\n"
                             "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n"
                             "%s\r\n",
                             chat_id);
    if (part_chat_len <= 0 || part_chat_len >= (int)sizeof(part_chat)) {
        free(url);
        free(resp.buf);
        return ESP_ERR_INVALID_SIZE;
    }

    if (caption && caption[0]) {
        part_caption_len = snprintf(part_caption, sizeof(part_caption),
                                    "--" CAP_IM_TG_MULTIPART_BOUNDARY "\r\n"
                                    "Content-Disposition: form-data; name=\"caption\"\r\n\r\n"
                                    "%s\r\n",
                                    caption);
        if (part_caption_len <= 0 || part_caption_len >= (int)sizeof(part_caption)) {
            free(url);
            free(resp.buf);
            return ESP_ERR_INVALID_SIZE;
        }
    }

    part_file_len = snprintf(part_file, sizeof(part_file),
                             "--" CAP_IM_TG_MULTIPART_BOUNDARY "\r\n"
                             "Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                             "Content-Type: %s\r\n\r\n",
                             field_name,
                             file_name,
                             mime);
    if (part_file_len <= 0 || part_file_len >= (int)sizeof(part_file)) {
        free(url);
        free(resp.buf);
        return ESP_ERR_INVALID_SIZE;
    }

    closing_len = snprintf(closing, sizeof(closing),
                           "\r\n--" CAP_IM_TG_MULTIPART_BOUNDARY "--\r\n");
    if (closing_len <= 0 || closing_len >= (int)sizeof(closing)) {
        free(url);
        free(resp.buf);
        return ESP_ERR_INVALID_SIZE;
    }

    content_length = (size_t)part_chat_len + (size_t)part_caption_len +
                     (size_t)part_file_len + (size_t)st.st_size + (size_t)closing_len;

    file = fopen(path, "rb");
    if (!file) {
        free(url);
        free(resp.buf);
        return ESP_FAIL;
    }

    config.url = url;
    config.method = HTTP_METHOD_POST;
    config.event_handler = cap_im_tg_http_event_handler;
    config.user_data = &resp;
    config.timeout_ms = (CAP_IM_TG_POLL_TIMEOUT_S + 5) * 1000;
    config.buffer_size = 2048;
    config.buffer_size_tx = 2048;
    config.crt_bundle_attach = esp_crt_bundle_attach;
#ifdef CONFIG_HTTP_REUSE_ENABLE
    config.keep_alive_enable = true;
#endif

    client = esp_http_client_init(&config);
    if (!client) {
        fclose(file);
        free(url);
        free(resp.buf);
        return ESP_FAIL;
    }

    snprintf(content_type,
             sizeof(content_type),
             "multipart/form-data; boundary=" CAP_IM_TG_MULTIPART_BOUNDARY);
    esp_http_client_set_header(client, "Content-Type", content_type);

    err = esp_http_client_open(client, (int)content_length);
    if (err == ESP_OK) {
        err = cap_im_tg_http_client_write_all(client, part_chat, (size_t)part_chat_len);
    }
    if (err == ESP_OK && part_caption_len > 0) {
        err = cap_im_tg_http_client_write_all(client, part_caption, (size_t)part_caption_len);
    }
    if (err == ESP_OK) {
        err = cap_im_tg_http_client_write_all(client, part_file, (size_t)part_file_len);
    }
    if (err == ESP_OK) {
        err = cap_im_tg_stream_file_to_http_client(client, file);
    }
    if (err == ESP_OK) {
        err = cap_im_tg_http_client_write_all(client, closing, (size_t)closing_len);
    }
    if (err == ESP_OK) {
        if (esp_http_client_fetch_headers(client) < 0) {
            err = ESP_FAIL;
        }
    }

    status = esp_http_client_get_status_code(client);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    fclose(file);
    free(url);

    if (err != ESP_OK) {
        free(resp.buf);
        return err;
    }
    if (status != 200) {
        ESP_LOGE(TAG, "Telegram %s failed: http=%d body=%s", method, status, resp.buf ? resp.buf : "");
        free(resp.buf);
        return ESP_FAIL;
    }

    free(resp.buf);
    return ESP_OK;
}

static esp_err_t cap_im_tg_send_media(const char *chat_id,
                                      const char *path,
                                      const char *caption,
                                      bool is_image)
{
    esp_err_t err;
    const char *method = is_image ? "sendPhoto" : "sendDocument";
    const char *field_name = is_image ? "photo" : "document";

    err = cap_im_tg_send_multipart_file(method, field_name, chat_id, path, caption, is_image);
    if (err != ESP_OK) {
        ESP_LOGE(TAG,
                 "Telegram %s send failed chat=%s path=%s err=%s",
                 is_image ? "image" : "file",
                 chat_id ? chat_id : "",
                 path ? path : "",
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG,
             "Telegram %s send success to %s: %s",
             is_image ? "image" : "file",
             chat_id,
             path);
    return ESP_OK;
}

/* Publishes the enabled s_tg_commands as the bot menu; true when Telegram took it. */
static bool cap_im_tg_set_commands(uint32_t mask)
{
    cJSON *body = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(body, "commands");
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err = ESP_ERR_NO_MEM;

    for (size_t i = 0; list && i < CAP_IM_TG_COMMAND_COUNT; i++) {
        cJSON *item;

        if (!(mask & (1u << i))) {
            continue;
        }
        item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "command", s_tg_commands[i].name);
        cJSON_AddStringToObject(item, "description", s_tg_commands[i].description);
        cJSON_AddItemToArray(list, item);
    }
    body_json = list ? cJSON_PrintUnformatted(body) : NULL;
    cJSON_Delete(body);
    if (body_json) {
        err = cap_im_tg_api_call("setMyCommands", body_json, &resp);
    }
    free(body_json);
    free(resp);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Telegram setMyCommands failed: %s", esp_err_to_name(err));
    }
    return err == ESP_OK;
}

static void cap_im_tg_poll_task(void *arg)
{
    uint32_t published_mask = UINT32_MAX;

    (void)arg;

    while (!s_tg.stop_requested) {
        /* Capabilities may register after the poll task starts: republish when the set changes. */
        uint32_t mask = cap_im_tg_command_mask();

        if (mask != published_mask && cap_im_tg_set_commands(mask)) {
            published_mask = mask;
        }
        if (cap_im_tg_poll_once() == ESP_OK) {
            s_tg_online = true;
        } else {
            if (s_tg.stop_requested) {
                break;
            }

            ESP_LOGW(TAG, "Telegram polling failed, retrying");
            vTaskDelay(pdMS_TO_TICKS(CAP_IM_TG_RETRY_DELAY_MS));
        }
    }

    s_tg.poll_task = NULL;
    claw_task_delete(NULL);
}

bool cap_im_tg_is_online(void)
{
    return s_tg_online;
}

static esp_err_t cap_im_tg_gateway_init(void)
{
    if (s_tg.bot_token[0] == '\0') {
        ESP_LOGW(TAG, "Telegram bot token not configured");
        return ESP_OK;
    }

    ESP_LOGI(TAG, "Telegram configured");
    return ESP_OK;
}

static esp_err_t cap_im_tg_gateway_start(void)
{
    BaseType_t ok;

    if (s_tg.bot_token[0] == '\0') {
        ESP_LOGW(TAG, "Telegram not configured, skipping start");
        return ESP_OK;
    }
    if (s_tg.poll_task) {
        return ESP_OK;
    }
    if (s_tg.allowed_user_count == 0) {
        ESP_LOGW(TAG, "tg_allowed_user_ids empty: all Telegram messages will be ignored");
    } else {
        ESP_LOGI(TAG, "Telegram allowlist: %u user(s)", (unsigned)s_tg.allowed_user_count);
    }

    s_tg.stop_requested = false;
    if (!s_tg.attachment_queue) {
        s_tg.attachment_queue = xQueueCreate(CAP_IM_TG_ATTACHMENT_QUEUE_LEN,
                                             sizeof(cap_im_tg_attachment_job_t *));
        if (!s_tg.attachment_queue) {
            return ESP_ERR_NO_MEM;
        }
    }
    ok = claw_task_create(&(claw_task_config_t){
                              .name = "tg_attach",
                              .stack_size = 10240,
                              .priority = 5,
                              .core_id = tskNO_AFFINITY,
                              .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                          },
                          cap_im_tg_attachment_task,
                          NULL,
                          &s_tg.attachment_task);
    if (ok != pdPASS) {
        vQueueDelete(s_tg.attachment_queue);
        s_tg.attachment_queue = NULL;
        s_tg.attachment_task = NULL;
        return ESP_FAIL;
    }
    ok = claw_task_create(&(claw_task_config_t){
                              .name = "tg_poll",
                              .stack_size = 6144,
                              .priority = 5,
                              .core_id = tskNO_AFFINITY,
                              .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                          },
                          cap_im_tg_poll_task,
                          NULL,
                          &s_tg.poll_task);
    if (ok != pdPASS) {
        s_tg.stop_requested = true;
        s_tg.poll_task = NULL;
        while (s_tg.attachment_task) {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
        vQueueDelete(s_tg.attachment_queue);
        s_tg.attachment_queue = NULL;
        return ESP_FAIL;
    }
    /* The busy indicator is cosmetic: run without it if the task cannot be created. */
    ok = claw_task_create(&(claw_task_config_t){
                              .name = "tg_busy",
                              .stack_size = 6144,
                              .priority = 4,
                              .core_id = tskNO_AFFINITY,
                              .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                          },
                          cap_im_tg_busy_task,
                          NULL,
                          &s_tg.busy_task);
    if (ok == pdPASS) {
        claw_core_set_progress_observer(cap_im_tg_busy_progress);
    } else {
        s_tg.busy_task = NULL;
        ESP_LOGW(TAG, "Telegram busy indicator task not started");
    }

    return ESP_OK;
}

static esp_err_t cap_im_tg_gateway_stop(void)
{
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(5000);

    if (!s_tg.poll_task) {
        return ESP_OK;
    }

    claw_core_set_progress_observer(NULL);
    s_tg.stop_requested = true;
    while (s_tg.poll_task && xTaskGetTickCount() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    if (s_tg.poll_task) {
        return ESP_ERR_TIMEOUT;
    }

    while (s_tg.attachment_task && xTaskGetTickCount() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    if (s_tg.attachment_task) {
        return ESP_ERR_TIMEOUT;
    }

    while (s_tg.busy_task && xTaskGetTickCount() < deadline) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    if (s_tg.busy_task) {
        return ESP_ERR_TIMEOUT;
    }

    if (s_tg.attachment_queue) {
        cap_im_tg_attachment_job_t *job = NULL;

        while (xQueueReceive(s_tg.attachment_queue, &job, 0) == pdTRUE) {
            cap_im_tg_free_attachment_job(job);
        }
        vQueueDelete(s_tg.attachment_queue);
        s_tg.attachment_queue = NULL;
    }

    return ESP_OK;
}

static esp_err_t cap_im_tg_send_message_execute(const char *input_json,
                                                const claw_cap_call_context_t *ctx,
                                                char *output,
                                                size_t output_size)
{
    cJSON *root = NULL;
    cJSON *chat_id_json;
    cJSON *message_json;
    const char *chat_id = NULL;
    const char *message = NULL;
    esp_err_t err;

    root = cJSON_Parse(input_json ? input_json : "{}");
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON");
        return ESP_ERR_INVALID_ARG;
    }

    chat_id_json = cJSON_GetObjectItem(root, "chat_id");
    message_json = cJSON_GetObjectItem(root, "message");
    if (cJSON_IsString(chat_id_json) && chat_id_json->valuestring && chat_id_json->valuestring[0]) {
        chat_id = chat_id_json->valuestring;
    } else if (ctx && ctx->chat_id && ctx->chat_id[0]) {
        chat_id = ctx->chat_id;
    }
    if (cJSON_IsString(message_json) && message_json->valuestring && message_json->valuestring[0]) {
        message = message_json->valuestring;
    }

    if (!chat_id || !message) {
        cJSON_Delete(root);
        snprintf(output,
                 output_size,
                 "Error: chat_id and message are required (chat_id may come from ctx)");
        return ESP_ERR_INVALID_ARG;
    }

    err = cap_im_tg_send_text(chat_id, message);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: %s", esp_err_to_name(err));
        return err;
    }

    snprintf(output, output_size, "reply already sent to user");
    return ESP_OK;
}

static esp_err_t cap_im_tg_send_media_execute(const char *input_json,
                                              const claw_cap_call_context_t *ctx,
                                              char *output,
                                              size_t output_size,
                                              bool is_image)
{
    cJSON *root = NULL;
    cJSON *chat_id_json;
    cJSON *path_json;
    cJSON *caption_json;
    const char *chat_id = NULL;
    const char *path = NULL;
    const char *caption = NULL;
    esp_err_t err;

    root = cJSON_Parse(input_json ? input_json : "{}");
    if (!root) {
        snprintf(output, output_size, "Error: invalid JSON");
        return ESP_ERR_INVALID_ARG;
    }

    chat_id_json = cJSON_GetObjectItem(root, "chat_id");
    path_json = cJSON_GetObjectItem(root, "path");
    caption_json = cJSON_GetObjectItem(root, "caption");
    if (cJSON_IsString(chat_id_json) && chat_id_json->valuestring && chat_id_json->valuestring[0]) {
        chat_id = chat_id_json->valuestring;
    } else if (ctx && ctx->chat_id && ctx->chat_id[0]) {
        chat_id = ctx->chat_id;
    }
    if (cJSON_IsString(path_json) && path_json->valuestring && path_json->valuestring[0]) {
        path = path_json->valuestring;
    }
    if (cJSON_IsString(caption_json) && caption_json->valuestring) {
        caption = caption_json->valuestring;
    }

    if (!chat_id || !path) {
        cJSON_Delete(root);
        snprintf(output,
                 output_size,
                 "Error: chat_id and path are required (chat_id may come from ctx)");
        return ESP_ERR_INVALID_ARG;
    }

    err = cap_im_tg_send_media(chat_id, path, caption, is_image);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: %s", esp_err_to_name(err));
        return err;
    }

    snprintf(output, output_size, "reply already sent to user");
    return ESP_OK;
}

static esp_err_t cap_im_tg_send_image_execute(const char *input_json,
                                              const claw_cap_call_context_t *ctx,
                                              char *output,
                                              size_t output_size)
{
    return cap_im_tg_send_media_execute(input_json, ctx, output, output_size, true);
}

static esp_err_t cap_im_tg_send_file_execute(const char *input_json,
                                             const claw_cap_call_context_t *ctx,
                                             char *output,
                                             size_t output_size)
{
    return cap_im_tg_send_media_execute(input_json, ctx, output, output_size, false);
}

static const claw_cap_descriptor_t s_tg_descriptors[] = {
    {
        .id = "tg_gateway",
        .name = "tg_gateway",
        .family = "im",
        .description = "Telegram bot polling gateway event source.",
        .kind = CLAW_CAP_KIND_EVENT_SOURCE,
        .cap_flags = CLAW_CAP_FLAG_EMITS_EVENTS |
        CLAW_CAP_FLAG_SUPPORTS_LIFECYCLE,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .init = cap_im_tg_gateway_init,
        .start = cap_im_tg_gateway_start,
        .stop = cap_im_tg_gateway_stop,
    },
    {
        .id = "tg_send_message",
        .name = "tg_send_message",
        .family = "im",
        .description = "Send a text message to an explicit Telegram chat_id.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"chat_id\":{\"type\":\"string\"},\"message\":{\"type\":\"string\"}},\"required\":[\"chat_id\",\"message\"]}",
        .execute = cap_im_tg_send_message_execute,
    },
    {
        .id = "tg_send_image",
        .name = "tg_send_image",
        .family = "im",
        .description = "Send an image file from a local path to a Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"chat_id\":{\"type\":\"string\"},\"path\":{\"type\":\"string\"},\"caption\":{\"type\":\"string\"}},\"required\":[\"path\"]}",
        .execute = cap_im_tg_send_image_execute,
    },
    {
        .id = "tg_send_file",
        .name = "tg_send_file",
        .family = "im",
        .description = "Send a file from a local path to a Telegram chat.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"chat_id\":{\"type\":\"string\"},\"path\":{\"type\":\"string\"},\"caption\":{\"type\":\"string\"}},\"required\":[\"path\"]}",
        .execute = cap_im_tg_send_file_execute,
    },
};

static const claw_cap_group_t s_tg_group = {
    .group_id = "cap_im_tg",
    .descriptors = s_tg_descriptors,
    .descriptor_count = sizeof(s_tg_descriptors) / sizeof(s_tg_descriptors[0]),
};

esp_err_t cap_im_tg_register_group(void)
{
    cap_im_tg_init_defaults();

    if (claw_cap_group_exists(s_tg_group.group_id)) {
        return ESP_OK;
    }

    return claw_cap_register_group(&s_tg_group);
}

esp_err_t cap_im_tg_set_token(const char *bot_token)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!bot_token) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_tg.bot_token, bot_token, sizeof(s_tg.bot_token));
    s_tg.next_update_id = 0;
    memset(s_tg.seen_update_keys, 0, sizeof(s_tg.seen_update_keys));
    s_tg.seen_update_idx = 0;
    return ESP_OK;
}

esp_err_t cap_im_tg_set_allowed_user_ids(const char *user_ids_csv)
{
    const char *cursor = user_ids_csv;

    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!user_ids_csv) {
        return ESP_ERR_INVALID_ARG;
    }

    s_tg.allowed_user_count = 0;
    while (*cursor) {
        char *end = NULL;
        long long id;

        while (*cursor == ',' || isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }

        errno = 0;
        id = strtoll(cursor, &end, 10);
        if (end == cursor || errno == ERANGE || id <= 0 ||
                (*end && *end != ',' && !isspace((unsigned char)*end))) {
            ESP_LOGW(TAG, "Ignoring invalid entry in tg_allowed_user_ids");
            cursor += strcspn(cursor, ",");
            continue;
        }
        if (s_tg.allowed_user_count >= CAP_IM_TG_MAX_ALLOWED_USERS) {
            ESP_LOGW(TAG, "tg_allowed_user_ids exceeds %d entries, ignoring the rest",
                     CAP_IM_TG_MAX_ALLOWED_USERS);
            break;
        }
        s_tg.allowed_user_ids[s_tg.allowed_user_count++] = (int64_t)id;
        cursor = end;
    }

    return ESP_OK;
}

esp_err_t cap_im_tg_set_stt_config(const char *base_url, const char *api_key, const char *model)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!base_url || !api_key || !model) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_tg.stt_base_url, base_url, sizeof(s_tg.stt_base_url));
    strlcpy(s_tg.stt_api_key, api_key, sizeof(s_tg.stt_api_key));
    strlcpy(s_tg.stt_model, model, sizeof(s_tg.stt_model));
    return ESP_OK;
}

esp_err_t cap_im_tg_set_attachment_config(
    const cap_im_tg_attachment_config_t *config)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (!config) {
        return ESP_ERR_INVALID_ARG;
    }

    s_tg.enable_inbound_attachments = config->enable_inbound_attachments;
    s_tg.max_inbound_file_bytes = config->max_inbound_file_bytes;
    if (config->storage_root_dir) {
        strlcpy(s_tg.attachment_root_dir,
                config->storage_root_dir,
                sizeof(s_tg.attachment_root_dir));
    } else {
        s_tg.attachment_root_dir[0] = '\0';
    }

    return ESP_OK;
}

esp_err_t cap_im_tg_start(void)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_tg.bot_token[0] == '\0') {
        ESP_LOGE(TAG, "Telegram bot token is not configured");
        return ESP_ERR_INVALID_STATE;
    }

    return cap_im_tg_gateway_start();
}

esp_err_t cap_im_tg_stop(void)
{
    return cap_im_tg_gateway_stop();
}

static esp_err_t cap_im_tg_send_text_legacy(const char *chat_id, const char *text)
{
    size_t text_len;
    size_t offset = 0;
    esp_err_t last_err = ESP_OK;

    text_len = strlen(text);
    while (offset < text_len) {
        size_t chunk_len = text_len - offset;
        char *chunk = NULL;
        esp_err_t err;

        if (chunk_len > CAP_IM_TG_MAX_MSG_LEN) {
            chunk_len = claw_utils_utf8_prefix_len(text + offset, CAP_IM_TG_MAX_MSG_LEN);
            if (chunk_len == 0) {
                return ESP_ERR_INVALID_ARG;
            }
        }

        chunk = calloc(1, chunk_len + 1);
        if (!chunk) {
            return ESP_ERR_NO_MEM;
        }

        memcpy(chunk, text + offset, chunk_len);
        err = cap_im_tg_send_text_chunk(chat_id, chunk);
        free(chunk);
        if (err != ESP_OK) {
            last_err = err;
        }

        offset += chunk_len;
    }

    return last_err;
}

esp_err_t cap_im_tg_send_text(const char *chat_id, const char *text)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }

    size_t text_len;
    size_t offset = 0;
    esp_err_t last_err = ESP_OK;

    if (!chat_id || !text || text[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_tg.bot_token[0] == '\0') {
        return ESP_ERR_INVALID_STATE;
    }

    text_len = strlen(text);
    while (offset < text_len) {
        size_t chunk_len = cap_im_tg_rich_chunk_len(text + offset, text_len - offset);
        char *chunk = NULL;
        esp_err_t err = ESP_FAIL;
        int status = 0;

        if (chunk_len == 0) {
            return ESP_ERR_INVALID_ARG;
        }
        chunk = calloc(1, chunk_len + 1);
        if (!chunk) {
            return ESP_ERR_NO_MEM;
        }

        memcpy(chunk, text + offset, chunk_len);
        if (!s_tg_rich_unsupported) {
            /* Adds at most 2 bytes per line: still within the rich limits after chunking. */
            char *md = cap_im_tg_md_hard_breaks(chunk);

            err = cap_im_tg_send_rich_chunk(chat_id, md ? md : chunk, &status);
            free(md);
        }
        /* Fall back on Telegram rejecting the rich message (parse/feature error, unknown method).
         * Transport errors are not retried: Telegram may already have accepted the message. */
        if (s_tg_rich_unsupported || (err == ESP_FAIL && (status == 400 || status == 404))) {
            if (status == 404 && !s_tg_rich_unsupported) {
                s_tg_rich_unsupported = true;
                ESP_LOGW(TAG, "sendRichMessage not available, using sendMessage until reboot");
            } else if (status == 400) {
                ESP_LOGW(TAG, "sendRichMessage rejected, falling back to sendMessage for this chunk");
            }
            err = cap_im_tg_send_text_legacy(chat_id, chunk);
        }
        free(chunk);
        if (err != ESP_OK) {
            last_err = err;
        }

        offset += chunk_len;
    }

    return last_err;
}

esp_err_t cap_im_tg_send_text_to_allowed(const char *text)
{
    esp_err_t ret = ESP_ERR_NOT_FOUND;
    char chat_id[24];

    /* A private chat has the user's id. */
    for (size_t i = 0; i < s_tg.allowed_user_count; i++) {
        snprintf(chat_id, sizeof(chat_id), "%" PRId64, s_tg.allowed_user_ids[i]);
        if (cap_im_tg_send_text(chat_id, text) == ESP_OK) {
            ret = ESP_OK;
        } else if (ret != ESP_OK) {
            ret = ESP_FAIL;
        }
    }
    return ret;
}

esp_err_t cap_im_tg_send_image(const char *chat_id, const char *path, const char *caption)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    return cap_im_tg_send_media(chat_id, path, caption, true);
}

esp_err_t cap_im_tg_send_file(const char *chat_id, const char *path, const char *caption)
{
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    return cap_im_tg_send_media(chat_id, path, caption, false);
}

/* Sends `html` with optional inline keyboard rows (ownership passes here) and returns its message id. */
static esp_err_t cap_im_tg_send_html_markup(const char *chat_id, const char *html, cJSON *rows,
                                            int64_t *out_message_id)
{
    cJSON *body = cJSON_CreateObject();
    cJSON *root = NULL;
    cJSON *message_id_json = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err;

    cJSON_AddStringToObject(body, "chat_id", chat_id);
    cJSON_AddStringToObject(body, "text", html);
    cJSON_AddStringToObject(body, "parse_mode", "HTML");
    if (rows) {
        cJSON_AddItemToObject(cJSON_AddObjectToObject(body, "reply_markup"), "inline_keyboard", rows);
    }
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return ESP_ERR_NO_MEM;
    }

    err = cap_im_tg_api_call("sendMessage", body_json, &resp);
    free(body_json);
    if (err == ESP_OK) {
        root = cJSON_Parse(resp);
        message_id_json = cJSON_GetObjectItem(cJSON_GetObjectItem(root, "result"), "message_id");
        if (cJSON_IsNumber(message_id_json)) {
            *out_message_id = (int64_t)message_id_json->valuedouble;
        } else {
            err = ESP_FAIL;
        }
        cJSON_Delete(root);
    }
    free(resp);
    return err;
}

esp_err_t cap_im_tg_send_html(const char *chat_id, const char *html, int64_t *out_message_id)
{
    if (!chat_id || !chat_id[0] || !html || !out_message_id) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_tg_initialized) {
        return ESP_ERR_INVALID_STATE;
    }
    return cap_im_tg_send_html_markup(chat_id, html, NULL, out_message_id);
}

esp_err_t cap_im_tg_confirm(const char *chat_id, const char *html, const char *const *labels, size_t label_count,
                            uint32_t timeout_ms, int *out_choice, int64_t *out_message_id)
{
    char nonce[CAP_IM_TG_CONFIRM_NONCE_LEN + 1];
    char data[32];
    cJSON *rows = NULL;
    esp_err_t err;

    if (!chat_id || !chat_id[0] || !html || !labels || label_count < 1 || label_count > 10 || !out_choice ||
            !out_message_id) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_tg_initialized || !s_confirm.lock || !s_confirm.answered) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xTaskGetCurrentTaskHandle() == s_tg.poll_task) {
        return ESP_ERR_INVALID_STATE;
    }

    snprintf(nonce, sizeof(nonce), "%08" PRIx32 "%08" PRIx32, esp_random(), esp_random());
    /* One button per row so long labels stay readable. */
    rows = cJSON_CreateArray();
    for (size_t i = 0; i < label_count; i++) {
        cJSON *button = cJSON_CreateObject();
        cJSON *row = cJSON_CreateArray();

        snprintf(data, sizeof(data), CAP_IM_TG_CONFIRM_PREFIX "%s:%u", nonce, (unsigned)i);
        cJSON_AddStringToObject(button, "text", labels[i]);
        cJSON_AddStringToObject(button, "callback_data", data);
        cJSON_AddItemToArray(row, button);
        cJSON_AddItemToArray(rows, row);
    }

    xSemaphoreTake(s_confirm.lock, portMAX_DELAY);
    /* Drop a give left over from an answer that raced the previous timeout. */
    xSemaphoreTake(s_confirm.answered, 0);
    taskENTER_CRITICAL(&s_confirm_mux);
    strlcpy(s_confirm.nonce, nonce, sizeof(s_confirm.nonce));
    strlcpy(s_confirm.chat_id, chat_id, sizeof(s_confirm.chat_id));
    s_confirm.choice_count = (int)label_count;
    s_confirm.choice = -1;
    taskEXIT_CRITICAL(&s_confirm_mux);

    err = cap_im_tg_send_html_markup(chat_id, html, rows, out_message_id);
    if (err == ESP_OK) {
        xSemaphoreTake(s_confirm.answered, pdMS_TO_TICKS(timeout_ms));
    }
    /* The poll task clears the nonce when it accepts an answer, so this also catches an answer
     * that arrived just as the wait timed out. */
    taskENTER_CRITICAL(&s_confirm_mux);
    *out_choice = s_confirm.nonce[0] == '\0' ? s_confirm.choice : -1;
    s_confirm.nonce[0] = '\0';
    taskEXIT_CRITICAL(&s_confirm_mux);
    xSemaphoreGive(s_confirm.lock);
    return err;
}

esp_err_t cap_im_tg_edit_message(const char *chat_id, int64_t message_id, const char *html)
{
    cJSON *body = NULL;
    char *body_json = NULL;
    char *resp = NULL;
    esp_err_t err;

    if (!chat_id || !html) {
        return ESP_ERR_INVALID_ARG;
    }

    body = cJSON_CreateObject();
    cJSON_AddStringToObject(body, "chat_id", chat_id);
    cJSON_AddNumberToObject(body, "message_id", (double)message_id);
    cJSON_AddStringToObject(body, "text", html);
    cJSON_AddStringToObject(body, "parse_mode", "HTML");
    body_json = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!body_json) {
        return ESP_ERR_NO_MEM;
    }

    err = cap_im_tg_api_call("editMessageText", body_json, &resp);
    free(body_json);
    free(resp);
    return err;
}
