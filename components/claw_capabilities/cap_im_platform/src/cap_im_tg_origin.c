/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_im_tg.h"

#include <stdio.h>
#include <string.h>

static bool cap_im_tg_str_is(const char *value, const char *expected)
{
    return value && strcmp(value, expected) == 0;
}

static bool cap_im_tg_is_subagent(const claw_cap_call_context_t *ctx)
{
    return ctx->caller == CLAW_CAP_CALLER_SUB_AGENT && ctx->agent_id && ctx->agent_id[0];
}

/* Work a scheduler job started: the root agent, or a subagent of one (claw_agent_mgr prefixes its source). */
static bool cap_im_tg_is_scheduler_origin(const claw_cap_call_context_t *ctx)
{
    if (ctx->caller == CLAW_CAP_CALLER_ROOT_AGENT || ctx->caller == CLAW_CAP_CALLER_SYSTEM) {
        return cap_im_tg_str_is(ctx->source_cap, CLAW_CAP_SOURCE_SCHEDULER);
    }
    return cap_im_tg_is_subagent(ctx) &&
           cap_im_tg_str_is(ctx->source_cap, CLAW_CAP_SOURCE_SUBAGENT_PREFIX CLAW_CAP_SOURCE_SCHEDULER);
}

const char *cap_im_tg_confirm_chat(const claw_cap_call_context_t *ctx)
{
    if (ctx && cap_im_tg_is_scheduler_origin(ctx)) {
        return cap_im_tg_cron_chat(cap_im_tg_str_is(ctx->channel, "telegram") ? ctx->chat_id : NULL);
    }
    if (!ctx || !cap_im_tg_str_is(ctx->channel, "telegram") || !ctx->chat_id || !ctx->chat_id[0]) {
        return NULL;
    }
    if ((ctx->caller == CLAW_CAP_CALLER_ROOT_AGENT || ctx->caller == CLAW_CAP_CALLER_SYSTEM) &&
            cap_im_tg_str_is(ctx->source_cap, CLAW_CAP_SOURCE_TG_GATEWAY)) {
        return ctx->chat_id;
    }
    if (cap_im_tg_is_subagent(ctx) && cap_im_tg_str_is(ctx->source_cap, CLAW_CAP_SOURCE_SUBAGENT_PREFIX CLAW_CAP_SOURCE_TG_GATEWAY)) {
        return ctx->chat_id;
    }
    return NULL;
}

size_t cap_im_tg_confirm_note(const claw_cap_call_context_t *ctx, char *html, size_t size)
{
    char note[160];
    size_t note_len = 0;
    size_t len = strlen(html);

    if (!ctx || !cap_im_tg_is_subagent(ctx)) {
        return len;
    }
    note_len = (size_t)snprintf(note, sizeof(note), "🤖 Angefordert von Subagent <code>");
    for (const char *p = ctx->agent_id; *p && note_len + 16 < sizeof(note); p++) {
        const char *entity = *p == '&' ? "&amp;" : *p == '<' ? "&lt;" : *p == '>' ? "&gt;" : NULL;

        if (entity) {
            note_len += strlcpy(note + note_len, entity, sizeof(note) - note_len);
        } else {
            note[note_len++] = *p;
        }
    }
    note_len += strlcpy(note + note_len, "</code>\n", sizeof(note) - note_len);
    if (note_len >= size) {
        html[0] = '\0';
        return 0;
    }
    /* The note always goes in; a prompt that no longer fits loses its tail (Telegram then rejects the
     * broken HTML and the action is refused). */
    if (len + note_len >= size) {
        len = size - 1 - note_len;
    }
    memmove(html + note_len, html, len);
    memcpy(html, note, note_len);
    html[note_len + len] = '\0';
    return note_len + len;
}
