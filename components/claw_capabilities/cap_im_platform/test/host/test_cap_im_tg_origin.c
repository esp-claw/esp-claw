/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Host tests for cap_im_tg_origin.c; run with test/host/run.sh. */
#include <stdio.h>
#include <string.h>

#include "cap_im_tg.h"

static int s_failed;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            s_failed++;                                                 \
        }                                                               \
    } while (0)

#define SUB_ID "chat:telegram:42:default_01:subagent_01"

static claw_cap_call_context_t ctx(claw_cap_caller_t caller, const char *channel, const char *source_cap,
                                   const char *chat_id)
{
    return (claw_cap_call_context_t) {
        .caller = caller,
        .channel = channel,
        .source_cap = source_cap,
        .chat_id = chat_id,
        .agent_id = caller == CLAW_CAP_CALLER_SUB_AGENT ? SUB_ID : NULL,
    };
}

static void test_confirm_chat(void)
{
    claw_cap_call_context_t c;

    /* Root agent and slash commands on a Telegram message. */
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == c.chat_id);
    c = ctx(CLAW_CAP_CALLER_SYSTEM, "telegram", "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == c.chat_id);

    /* Subagent working for a Telegram root request. */
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr/tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == c.chat_id);
    c.agent_id = "";
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);

    /* Laundered: a scheduler/router/Lua root request that targets Telegram, and its subagents. */
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "cap_scheduler", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr/cap_scheduler", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr/", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr/tg_gateway_x", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    /* Old-style subagent source without origin, and the root handling a subagent completion. */
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "cap_agent_mgr", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    /* Only subagents get the cap_agent_mgr/ form. */
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "cap_agent_mgr/tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_SYSTEM, "telegram", "cap_agent_mgr/tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    /* A subagent never qualifies with the gateway's own source. */
    c = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);

    /* System callers other than the gateway: Lua call_capability, router actions, console. */
    c = ctx(CLAW_CAP_CALLER_SYSTEM, "telegram", "claw_event_router", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_SYSTEM, "telegram", NULL, "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_CONSOLE, "telegram", "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);

    /* Other channels and missing chat. */
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "local_im", "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, NULL, "tg_gateway", "42");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "tg_gateway", "");
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    c = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "tg_gateway", NULL);
    CHECK(cap_im_tg_confirm_chat(&c) == NULL);
    CHECK(cap_im_tg_confirm_chat(NULL) == NULL);
}

static void test_confirm_note(void)
{
    claw_cap_call_context_t root = ctx(CLAW_CAP_CALLER_ROOT_AGENT, "telegram", "tg_gateway", "42");
    claw_cap_call_context_t sub = ctx(CLAW_CAP_CALLER_SUB_AGENT, "telegram", "cap_agent_mgr/tg_gateway", "42");
    char html[256];
    char tiny[24];
    size_t len;

    strcpy(html, "<b>Prompt</b>");
    CHECK(cap_im_tg_confirm_note(&root, html, sizeof(html)) == strlen("<b>Prompt</b>"));
    CHECK(strcmp(html, "<b>Prompt</b>") == 0);

    len = cap_im_tg_confirm_note(&sub, html, sizeof(html));
    CHECK(len == strlen(html));
    CHECK(strcmp(html, "🤖 Angefordert von Subagent <code>" SUB_ID "</code>\n<b>Prompt</b>") == 0);

    /* The id is escaped. */
    sub.agent_id = "a<b>&c";
    strcpy(html, "x");
    cap_im_tg_confirm_note(&sub, html, sizeof(html));
    CHECK(strcmp(html, "🤖 Angefordert von Subagent <code>a&lt;b&gt;&amp;c</code>\nx") == 0);

    /* The note wins over the prompt's tail; without room for it the prompt is emptied. */
    sub.agent_id = "s";
    memset(html, 'p', 100);
    html[100] = '\0';
    len = cap_im_tg_confirm_note(&sub, html, 64);
    CHECK(len == 63 && strlen(html) == 63);
    CHECK(strncmp(html, "🤖 Angefordert von Subagent <code>s</code>\np", strlen("🤖 Angefordert von Subagent <code>s</code>\np")) == 0);
    strcpy(tiny, "abc");
    CHECK(cap_im_tg_confirm_note(&sub, tiny, sizeof(tiny)) == 0 && tiny[0] == '\0');
}

int main(void)
{
    test_confirm_chat();
    test_confirm_note();
    if (s_failed) {
        printf("%d check(s) failed\n", s_failed);
        return 1;
    }
    printf("all cap_im_tg_origin tests passed\n");
    return 0;
}
