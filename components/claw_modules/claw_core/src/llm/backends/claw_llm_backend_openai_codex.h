/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "llm/claw_llm_runtime.h"

#define CLAW_LLM_BACKEND_OPENAI_CODEX_ID "openai_codex"
#define CLAW_LLM_BACKEND_OPENAI_CODEX_BASE_URL "https://chatgpt.com/backend-api/codex"
#define CLAW_LLM_BACKEND_OPENAI_CODEX_DEFAULT_MODEL "gpt-6.1-sol"

const claw_llm_backend_vtable_t *claw_llm_backend_openai_codex_vtable(void);
const claw_llm_backend_registration_t *claw_llm_backend_openai_codex_registration(void);
