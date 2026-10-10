/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "claw_cap.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *storage_root_dir;
    size_t max_inbound_file_bytes;
    bool enable_inbound_attachments;
} cap_im_tg_attachment_config_t;

esp_err_t cap_im_tg_register_group(void);
esp_err_t cap_im_tg_set_token(const char *bot_token);
/* Comma-separated numeric Telegram user ids; an empty list drops every update. */
esp_err_t cap_im_tg_set_allowed_user_ids(const char *user_ids_csv);
/* Speech-to-text for inbound voice/audio; an empty api_key disables transcription. */
esp_err_t cap_im_tg_set_stt_config(const char *base_url, const char *api_key, const char *model);
esp_err_t cap_im_tg_set_attachment_config(
    const cap_im_tg_attachment_config_t *config);
esp_err_t cap_im_tg_start(void);
esp_err_t cap_im_tg_stop(void);
esp_err_t cap_im_tg_send_text(const char *chat_id, const char *text);
esp_err_t cap_im_tg_send_image(const char *chat_id, const char *path, const char *caption);
esp_err_t cap_im_tg_send_file(const char *chat_id, const char *path, const char *caption);
/* Sends `html` (Telegram HTML) without buttons; `out_message_id` is for cap_im_tg_edit_message(). */
esp_err_t cap_im_tg_send_html(const char *chat_id, const char *html, int64_t *out_message_id);
/*
 * Sends `html` with one inline button per label (at most 10; the last one rejects) and blocks
 * until an allowlisted user presses one in that chat or `timeout_ms` passes. `out_choice` is the
 * pressed label's index, or -1 on timeout. Calls are serialized. Must not run on the Telegram
 * poll task, which delivers the answer. `out_message_id` identifies the prompt for
 * cap_im_tg_edit_message().
 */
esp_err_t cap_im_tg_confirm(const char *chat_id, const char *html, const char *const *labels, size_t label_count,
                            uint32_t timeout_ms, int *out_choice, int64_t *out_message_id);
/* True once a getUpdates poll succeeded since boot (the bot token works and Telegram is reachable). */
bool cap_im_tg_is_online(void);
/* Replaces a sent message with `html` and removes its inline buttons. */
esp_err_t cap_im_tg_edit_message(const char *chat_id, int64_t message_id, const char *html);

#ifdef __cplusplus
}
#endif
