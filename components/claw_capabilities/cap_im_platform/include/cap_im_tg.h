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
/* Sends `text` to every allowed user's private chat; ESP_OK when it reached at least one. */
esp_err_t cap_im_tg_send_text_to_allowed(const char *text);
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
/*
 * The chat in which a mutating action requested with `ctx` may be confirmed, or NULL when it must be
 * refused. Only work that a message in an allowed Telegram chat started qualifies:
 * - the root agent, or a slash command (caller SYSTEM), on a request with source_cap "tg_gateway";
 * - a subagent on a request with source_cap "cap_agent_mgr/tg_gateway": claw_agent_mgr appends the
 *   source of the root request that spawned or fed it, so a subagent started by a scheduler, router
 *   or Web IM request ("cap_agent_mgr/cap_scheduler", ...) is refused even when it targets Telegram.
 * channel/chat_id are trusted only together with source_cap "tg_gateway", which Lua cannot claim.
 * The root agent handling a subagent's completion (source_cap "cap_agent_mgr") is refused.
 * While "/yolo cron" is on, scheduler work (source_cap "cap_scheduler" or "cap_agent_mgr/cap_scheduler")
 * qualifies too, in the request's own chat if that is an allowed Telegram chat, else in the first
 * allowed one (see cap_im_tg_cron_chat()); cap_im_tg_confirm() approves those prompts by itself.
 */
const char *cap_im_tg_confirm_chat(const claw_cap_call_context_t *ctx);
/*
 * The chat for a scheduler-started request while "/yolo cron" is on: `request_chat` if it is an allowed
 * Telegram chat, else the first allowed one; NULL when "/yolo cron" is off or nothing is allowed. The
 * result points to an internal buffer, which cap_im_tg_confirm() recognises as a scheduler origin.
 */
const char *cap_im_tg_cron_chat(const char *request_chat);
/*
 * For subagent calls, puts "requested by subagent <agent id>" in front of the NUL-terminated `html`
 * (buffer of `size` bytes), cutting the prompt's tail if needed. Returns the new length.
 */
size_t cap_im_tg_confirm_note(const claw_cap_call_context_t *ctx, char *html, size_t size);
/* True once a getUpdates poll succeeded since boot (the bot token works and Telegram is reachable). */
bool cap_im_tg_is_online(void);
/* Replaces a sent message with `html` and removes its inline buttons. */
esp_err_t cap_im_tg_edit_message(const char *chat_id, int64_t message_id, const char *html);

#ifdef __cplusplus
}
#endif
