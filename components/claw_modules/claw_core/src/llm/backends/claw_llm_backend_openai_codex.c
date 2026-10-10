/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "llm/backends/claw_llm_backend_openai_codex.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "llm/claw_llm_codex_auth.h"
#include "llm/claw_llm_http_transport.h"
#include "llm/media/claw_media_pipeline.h"

#define CODEX_INSTRUCTIONS_FALLBACK ""

typedef struct {
    char *model;
    char *base_url;
    uint32_t timeout_ms;
    size_t image_max_bytes;
} openai_codex_backend_ctx_t;

static char *dup_printf(const char *fmt, ...)
{
    va_list args;
    va_list copy;
    int needed;
    char *buf;

    va_start(args, fmt);
    va_copy(copy, args);
    needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(args);
        return NULL;
    }

    buf = calloc(1, (size_t)needed + 1);
    if (buf) {
        vsnprintf(buf, (size_t)needed + 1, fmt, args);
    }
    va_end(args);
    return buf;
}

static esp_err_t text_append(char **buf, size_t *len, const char *text)
{
    size_t add = strlen(text);
    char *grown = realloc(*buf, *len + add + 1);

    if (!grown) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(grown + *len, text, add + 1);
    *buf = grown;
    *len += add;
    return ESP_OK;
}

static const char *json_string(const cJSON *object, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(object, key);

    return cJSON_IsString(item) && item->valuestring ? item->valuestring : NULL;
}

static cJSON *input_text_part(const char *type, const char *text)
{
    cJSON *part = cJSON_CreateObject();

    if (part) {
        cJSON_AddStringToObject(part, "type", type);
        cJSON_AddStringToObject(part, "text", text);
    }
    return part;
}

/* Builds a Responses message item from a single user/system/developer message. */
static cJSON *build_message_item(const char *role, const cJSON *content)
{
    cJSON *item = cJSON_CreateObject();
    cJSON *parts = cJSON_CreateArray();
    const cJSON *part;

    if (!item || !parts) {
        cJSON_Delete(item);
        cJSON_Delete(parts);
        return NULL;
    }
    cJSON_AddStringToObject(item, "type", "message");
    cJSON_AddStringToObject(item, "role", role);
    cJSON_AddItemToObject(item, "content", parts);

    if (cJSON_IsString(content)) {
        cJSON_AddItemToArray(parts, input_text_part("input_text", content->valuestring));
    } else if (cJSON_IsArray(content)) {
        cJSON_ArrayForEach(part, content) {
            const char *type = json_string(part, "type");
            const char *text = json_string(part, "text");
            cJSON *image = NULL;

            if (type && strcmp(type, "text") == 0 && text) {
                cJSON_AddItemToArray(parts, input_text_part("input_text", text));
            } else if (type && strcmp(type, "image_url") == 0) {
                const cJSON *image_url = cJSON_GetObjectItemCaseSensitive(part, "image_url");
                const char *url = json_string(image_url, "url");

                image = cJSON_CreateObject();
                if (url && image) {
                    cJSON_AddStringToObject(image, "type", "input_image");
                    cJSON_AddStringToObject(image, "image_url", url);
                    cJSON_AddItemToArray(parts, image);
                } else {
                    cJSON_Delete(image);
                }
            }
        }
    }
    return item;
}

/* Converts Chat Completions style history (the agent loop format) into Responses input items. */
static cJSON *build_input(const cJSON *messages)
{
    cJSON *input = cJSON_CreateArray();
    const cJSON *message;

    if (!input) {
        return NULL;
    }
    cJSON_ArrayForEach(message, messages) {
        const char *role = json_string(message, "role");
        const cJSON *content = cJSON_GetObjectItemCaseSensitive(message, "content");
        cJSON *item = NULL;

        if (!role) {
            continue;
        }
        if (strcmp(role, "tool") == 0) {
            item = cJSON_CreateObject();
            if (item) {
                cJSON_AddStringToObject(item, "type", "function_call_output");
                cJSON_AddStringToObject(item, "call_id", json_string(message, "tool_call_id") ?: "");
                cJSON_AddStringToObject(item, "output", cJSON_IsString(content) ? content->valuestring : "");
            }
        } else if (strcmp(role, "assistant") == 0) {
            const cJSON *tool_calls = cJSON_GetObjectItemCaseSensitive(message, "tool_calls");
            const cJSON *call;

            if (content && cJSON_IsString(content) && content->valuestring[0]) {
                cJSON *text_item = cJSON_CreateObject();
                cJSON *parts = cJSON_CreateArray();
                cJSON *part = cJSON_CreateObject();

                if (!text_item || !parts || !part) {
                    cJSON_Delete(text_item);
                    cJSON_Delete(parts);
                    cJSON_Delete(part);
                    cJSON_Delete(input);
                    return NULL;
                }
                cJSON_AddStringToObject(part, "type", "output_text");
                cJSON_AddStringToObject(part, "text", content->valuestring);
                cJSON_AddItemToArray(parts, part);
                cJSON_AddStringToObject(text_item, "type", "message");
                cJSON_AddStringToObject(text_item, "role", "assistant");
                cJSON_AddItemToObject(text_item, "content", parts);
                cJSON_AddItemToArray(input, text_item);
            }
            cJSON_ArrayForEach(call, tool_calls) {
                const cJSON *function = cJSON_GetObjectItemCaseSensitive(call, "function");
                cJSON *fc = cJSON_CreateObject();

                if (fc) {
                    cJSON_AddStringToObject(fc, "type", "function_call");
                    cJSON_AddStringToObject(fc, "call_id", json_string(call, "id") ?: "");
                    cJSON_AddStringToObject(fc, "name", json_string(function, "name") ?: "");
                    cJSON_AddStringToObject(fc, "arguments", json_string(function, "arguments") ?: "{}");
                    cJSON_AddItemToArray(input, fc);
                }
            }
            continue;
        } else {
            item = build_message_item(role, content);
        }
        if (item) {
            cJSON_AddItemToArray(input, item);
        }
    }
    return input;
}

static cJSON *build_tools(const char *tools_json)
{
    cJSON *source = cJSON_Parse(tools_json);
    cJSON *tools = cJSON_CreateArray();
    const cJSON *tool;

    if (!source || !tools || !cJSON_IsArray(source)) {
        cJSON_Delete(source);
        cJSON_Delete(tools);
        return NULL;
    }
    cJSON_ArrayForEach(tool, source) {
        const cJSON *function = cJSON_GetObjectItemCaseSensitive(tool, "function");
        const cJSON *parameters = function ? cJSON_GetObjectItemCaseSensitive(function, "parameters") : NULL;
        cJSON *item = cJSON_CreateObject();

        if (!item || !function) {
            cJSON_Delete(item);
            continue;
        }
        cJSON_AddStringToObject(item, "type", "function");
        cJSON_AddStringToObject(item, "name", json_string(function, "name") ?: "");
        cJSON_AddStringToObject(item, "description", json_string(function, "description") ?: "");
        cJSON_AddItemToObject(item, "parameters",
                              parameters ? cJSON_Duplicate(parameters, true) : cJSON_CreateObject());
        cJSON_AddItemToArray(tools, item);
    }
    cJSON_Delete(source);
    return tools;
}

static esp_err_t add_tool_call(claw_llm_response_t *out,
                               const char *id,
                               const char *name,
                               const char *arguments)
{
    claw_llm_tool_call_t *grown;
    claw_llm_tool_call_t *dst;

    grown = realloc(out->tool_calls, (out->tool_call_count + 1) * sizeof(*grown));
    if (!grown) {
        return ESP_ERR_NO_MEM;
    }
    out->tool_calls = grown;
    dst = &grown[out->tool_call_count];
    memset(dst, 0, sizeof(*dst));
    out->tool_call_count++;
    dst->id = strdup(id);
    dst->name = strdup(name);
    dst->arguments_json = strdup(arguments);
    return dst->id && dst->name && dst->arguments_json ? ESP_OK : ESP_ERR_NO_MEM;
}

static void append_output_text(const cJSON *message, char **text, size_t *text_len)
{
    const cJSON *part;
    const cJSON *content = cJSON_GetObjectItemCaseSensitive(message, "content");

    cJSON_ArrayForEach(part, content) {
        const char *value = json_string(part, "text");

        if (json_string(part, "type") && strcmp(json_string(part, "type"), "output_text") == 0 && value) {
            text_append(text, text_len, value);
        }
    }
}

static esp_err_t handle_event(const cJSON *event,
                              char **text,
                              size_t *text_len,
                              claw_llm_response_t *out,
                              char **out_error_message)
{
    const char *type = json_string(event, "type");
    const cJSON *item;

    if (!type) {
        return ESP_OK;
    }
    if (strcmp(type, "response.output_text.delta") == 0) {
        const char *delta = json_string(event, "delta");

        return delta ? text_append(text, text_len, delta) : ESP_OK;
    }
    if (strcmp(type, "response.output_item.done") == 0) {
        const char *item_type;

        item = cJSON_GetObjectItemCaseSensitive(event, "item");
        item_type = json_string(item, "type");
        if (!item_type) {
            return ESP_OK;
        }
        if (strcmp(item_type, "function_call") == 0) {
            const char *call_id = json_string(item, "call_id");
            const char *name = json_string(item, "name");
            const char *arguments = json_string(item, "arguments");

            return add_tool_call(out, call_id ?: "", name ?: "", arguments ?: "{}");
        }
        if (strcmp(item_type, "message") == 0 && *text_len == 0) {
            append_output_text(item, text, text_len);
        }
        return ESP_OK;
    }
    if (strcmp(type, "response.failed") == 0 || strcmp(type, "error") == 0) {
        const cJSON *error = cJSON_GetObjectItemCaseSensitive(event, "error");
        const cJSON *response = cJSON_GetObjectItemCaseSensitive(event, "response");
        const char *message = json_string(error, "message");

        if (!message) {
            message = json_string(response ? cJSON_GetObjectItemCaseSensitive(response, "error") : NULL, "message");
        }
        *out_error_message = dup_printf("Codex request failed: %s", message ?: "unknown error");
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Parses the SSE body of a streamed Responses call into text and function calls. */
static esp_err_t parse_sse_response(const char *body, claw_llm_response_t *out, char **out_error_message)
{
    const char *line = body;
    char *text = NULL;
    size_t text_len = 0;
    esp_err_t err = ESP_OK;
    cJSON *message;

    memset(out, 0, sizeof(*out));
    while (line && *line && err == ESP_OK) {
        const char *eol = strchr(line, '\n');
        size_t len = eol ? (size_t)(eol - line) : strlen(line);

        if (len > 5 && strncmp(line, "data:", 5) == 0) {
            char *payload = calloc(1, len);
            const char *start = line + 5;
            cJSON *event;

            if (!payload) {
                err = ESP_ERR_NO_MEM;
                break;
            }
            while (*start == ' ') {
                start++;
            }
            memcpy(payload, start, len - (size_t)(start - line));
            event = cJSON_Parse(payload);
            free(payload);
            if (event) {
                err = handle_event(event, &text, &text_len, out, out_error_message);
                cJSON_Delete(event);
            }
        }
        line = eol ? eol + 1 : NULL;
    }

    if (err != ESP_OK) {
        free(text);
        claw_llm_response_free(out);
        if (!*out_error_message) {
            *out_error_message = dup_printf("Out of memory parsing Codex response");
        }
        return err;
    }
    if (!text && out->tool_call_count == 0) {
        *out_error_message = dup_printf("LLM returned empty text response");
        return ESP_FAIL;
    }

    /* Keep the agent history in the Chat Completions shape used by the other backends. */
    message = cJSON_CreateObject();
    if (!message) {
        free(text);
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(message, "role", "assistant");
    if (text) {
        cJSON_AddStringToObject(message, "content", text);
    } else {
        cJSON_AddNullToObject(message, "content");
    }
    if (out->tool_call_count > 0) {
        cJSON *calls = cJSON_AddArrayToObject(message, "tool_calls");
        size_t i;

        for (i = 0; calls && i < out->tool_call_count; i++) {
            cJSON *call = cJSON_CreateObject();
            cJSON *function = cJSON_CreateObject();

            if (!call || !function) {
                cJSON_Delete(call);
                cJSON_Delete(function);
                break;
            }
            cJSON_AddStringToObject(call, "id", out->tool_calls[i].id);
            cJSON_AddStringToObject(call, "type", "function");
            cJSON_AddStringToObject(function, "name", out->tool_calls[i].name);
            cJSON_AddStringToObject(function, "arguments", out->tool_calls[i].arguments_json);
            cJSON_AddItemToObject(call, "function", function);
            cJSON_AddItemToArray(calls, call);
        }
    }
    out->raw_message_json = cJSON_PrintUnformatted(message);
    cJSON_Delete(message);
    out->text = text;
    if (!out->raw_message_json) {
        claw_llm_response_free(out);
        *out_error_message = dup_printf("Out of memory copying LLM raw message");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/* Posts a Responses body with the current OAuth token. On HTTP 401 the token is refreshed once and retried. */
static esp_err_t send_responses(const openai_codex_backend_ctx_t *ctx,
                                const char *post_data,
                                volatile bool *abort_flag,
                                claw_llm_http_response_t *out_http,
                                char **out_error_message)
{
    char *url;
    esp_err_t err = ESP_FAIL;
    int attempt;

    url = dup_printf("%s%sresponses",
                     ctx->base_url,
                     ctx->base_url[strlen(ctx->base_url) - 1] == '/' ? "" : "/");
    if (!url) {
        *out_error_message = dup_printf("Out of memory building Codex URL");
        return ESP_ERR_NO_MEM;
    }

    for (attempt = 0; attempt < 2; attempt++) {
        claw_llm_http_header_t headers[2];
        claw_llm_http_json_request_t request = {0};
        char *token = NULL;
        char *account = NULL;

        err = claw_llm_codex_get_access_token(attempt > 0, &token, &account, out_error_message);
        if (err != ESP_OK) {
            break;
        }
        headers[0].name = "originator";
        headers[0].value = "codex_cli_rs";
        headers[1].name = "ChatGPT-Account-ID";
        headers[1].value = account;

        request.url = url;
        request.body = post_data;
        request.api_key = token;
        request.auth_type = "bearer";
        request.timeout_ms = ctx->timeout_ms;
        request.abort_flag = abort_flag;
        request.headers = headers;
        request.header_count = 2;
        err = claw_llm_http_post_json(&request, out_http, out_error_message);
        free(token);
        free(account);
        if (err == ESP_OK || out_http->status_code != 401) {
            break;
        }
        free(*out_error_message);
        *out_error_message = NULL;
        claw_llm_http_response_free(out_http);
    }
    free(url);
    return err;
}

static esp_err_t build_request_body(const openai_codex_backend_ctx_t *ctx,
                                    const char *instructions,
                                    cJSON *input,
                                    cJSON *tools,
                                    char **out_post_data,
                                    char **out_error_message)
{
    cJSON *body = cJSON_CreateObject();

    if (!body || !input) {
        cJSON_Delete(body);
        cJSON_Delete(input);
        cJSON_Delete(tools);
        *out_error_message = dup_printf("Out of memory building Codex request");
        return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(body, "model", ctx->model);
    cJSON_AddStringToObject(body, "instructions", instructions ?: CODEX_INSTRUCTIONS_FALLBACK);
    cJSON_AddItemToObject(body, "input", input);
    if (tools) {
        cJSON_AddItemToObject(body, "tools", tools);
        cJSON_AddStringToObject(body, "tool_choice", "auto");
        cJSON_AddTrueToObject(body, "parallel_tool_calls");
    }
    cJSON_AddTrueToObject(body, "stream");
    cJSON_AddFalseToObject(body, "store");

    *out_post_data = cJSON_PrintUnformatted(body);
    cJSON_Delete(body);
    if (!*out_post_data) {
        *out_error_message = dup_printf("Out of memory serializing Codex request");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static esp_err_t openai_codex_init(const claw_llm_runtime_config_t *config,
                                   const claw_llm_model_profile_t *profile,
                                   void **out_backend_ctx,
                                   char **out_error_message)
{
    openai_codex_backend_ctx_t *ctx;
    esp_err_t err;

    if (!config || !profile || !out_backend_ctx || !out_error_message) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!config->model || !config->model[0]) {
        *out_error_message = dup_printf("LLM model is empty");
        return ESP_ERR_INVALID_ARG;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        *out_error_message = dup_printf("Out of memory allocating backend context");
        return ESP_ERR_NO_MEM;
    }
    ctx->model = strdup(config->model);
    ctx->base_url = strdup(config->base_url && config->base_url[0] ?
                           config->base_url : CLAW_LLM_BACKEND_OPENAI_CODEX_BASE_URL);
    ctx->timeout_ms = config->timeout_ms;
    ctx->image_max_bytes = config->image_max_bytes;
    err = claw_llm_codex_auth_init();
    if (!ctx->model || !ctx->base_url || err != ESP_OK) {
        *out_error_message = dup_printf("Out of memory initializing Codex backend");
        free(ctx->model);
        free(ctx->base_url);
        free(ctx);
        return err != ESP_OK ? err : ESP_ERR_NO_MEM;
    }

    *out_backend_ctx = ctx;
    return ESP_OK;
}

static esp_err_t openai_codex_chat(void *backend_ctx,
                                   const claw_llm_model_profile_t *profile,
                                   const claw_llm_chat_request_t *request,
                                   claw_llm_response_t *out_response,
                                   char **out_error_message)
{
    openai_codex_backend_ctx_t *ctx = (openai_codex_backend_ctx_t *)backend_ctx;
    claw_llm_http_response_t http_response = {0};
    char *post_data = NULL;
    cJSON *tools = NULL;
    esp_err_t err;

    if (!ctx || !profile || !request || !request->messages || !out_response || !out_error_message) {
        return ESP_ERR_INVALID_ARG;
    }
    if (request->tools_json && request->tools_json[0]) {
        if (!profile->supports_tools) {
            *out_error_message = dup_printf("Selected backend does not support tool calls");
            return ESP_ERR_NOT_SUPPORTED;
        }
        tools = build_tools(request->tools_json);
        if (!tools) {
            *out_error_message = dup_printf("Invalid tools JSON");
            return ESP_ERR_INVALID_ARG;
        }
    }

    err = build_request_body(ctx, request->system_prompt, build_input(request->messages), tools,
                             &post_data, out_error_message);
    if (err != ESP_OK) {
        return err;
    }
    err = send_responses(ctx, post_data, request->abort_flag, &http_response, out_error_message);
    free(post_data);
    if (err != ESP_OK) {
        return err;
    }

    err = parse_sse_response(http_response.body, out_response, out_error_message);
    claw_llm_http_response_free(&http_response);
    return err;
}

static esp_err_t openai_codex_infer_media(void *backend_ctx,
                                          const claw_llm_model_profile_t *profile,
                                          const claw_llm_media_request_t *request,
                                          char **out_text,
                                          char **out_error_message)
{
    openai_codex_backend_ctx_t *ctx = (openai_codex_backend_ctx_t *)backend_ctx;
    claw_media_prepared_t prepared = {0};
    claw_llm_http_response_t http_response = {0};
    claw_llm_response_t response = {0};
    cJSON *content;
    cJSON *text_part;
    cJSON *image_part;
    cJSON *input;
    cJSON *item;
    char *post_data = NULL;
    esp_err_t err;

    if (out_text) {
        *out_text = NULL;
    }
    if (!ctx || !profile || !request || !out_text || !out_error_message) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!profile->supports_vision) {
        *out_error_message = dup_printf("Selected profile does not support media inference");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!request->user_prompt || !request->user_prompt[0] || !request->media || request->media_count == 0) {
        *out_error_message = dup_printf("media request is incomplete");
        return ESP_ERR_INVALID_ARG;
    }

    err = claw_media_prepare_asset(&request->media[0], profile, ctx->image_max_bytes, &prepared,
                                   out_error_message);
    if (err != ESP_OK) {
        return err;
    }

    input = cJSON_CreateArray();
    item = cJSON_CreateObject();
    content = cJSON_CreateArray();
    text_part = input_text_part("input_text", request->user_prompt);
    image_part = cJSON_CreateObject();
    if (!input || !item || !content || !text_part || !image_part) {
        err = ESP_ERR_NO_MEM;
        *out_error_message = dup_printf("Out of memory building media request");
        cJSON_Delete(input);
        cJSON_Delete(item);
        cJSON_Delete(content);
        cJSON_Delete(text_part);
        cJSON_Delete(image_part);
        goto cleanup;
    }
    cJSON_AddItemToArray(content, text_part);
    cJSON_AddStringToObject(image_part, "type", "input_image");
    cJSON_AddStringToObject(image_part, "image_url", prepared.payload);
    cJSON_AddItemToArray(content, image_part);
    cJSON_AddStringToObject(item, "type", "message");
    cJSON_AddStringToObject(item, "role", "user");
    cJSON_AddItemToObject(item, "content", content);
    cJSON_AddItemToArray(input, item);

    err = build_request_body(ctx, request->system_prompt, input, NULL, &post_data, out_error_message);
    if (err != ESP_OK) {
        goto cleanup;
    }
    err = send_responses(ctx, post_data, NULL, &http_response, out_error_message);
    if (err != ESP_OK) {
        goto cleanup;
    }
    err = parse_sse_response(http_response.body, &response, out_error_message);
    if (err != ESP_OK) {
        goto cleanup;
    }
    if (!response.text || !response.text[0]) {
        err = ESP_FAIL;
        *out_error_message = dup_printf("LLM returned empty media response");
        goto cleanup;
    }

    *out_text = response.text;
    response.text = NULL;

cleanup:
    free(post_data);
    claw_llm_http_response_free(&http_response);
    claw_llm_response_free(&response);
    claw_media_prepared_free(&prepared);
    return err;
}

static void openai_codex_deinit(void *backend_ctx)
{
    openai_codex_backend_ctx_t *ctx = (openai_codex_backend_ctx_t *)backend_ctx;

    if (!ctx) {
        return;
    }
    free(ctx->model);
    free(ctx->base_url);
    free(ctx);
}

static const claw_llm_backend_vtable_t s_openai_codex_vtable = {
    .id = CLAW_LLM_BACKEND_OPENAI_CODEX_ID,
    .init = openai_codex_init,
    .chat = openai_codex_chat,
    .infer_media = openai_codex_infer_media,
    .deinit = openai_codex_deinit,
};

static const claw_llm_backend_registration_t s_openai_codex_registration = {
    .id = CLAW_LLM_BACKEND_OPENAI_CODEX_ID,
    .vtable = &s_openai_codex_vtable,
    .defaults = {
        .auth_type = "bearer",
        .chat_path = "/responses",
        .max_tokens_field = "max_output_tokens",
    },
};

const claw_llm_backend_vtable_t *claw_llm_backend_openai_codex_vtable(void)
{
    return &s_openai_codex_vtable;
}

const claw_llm_backend_registration_t *claw_llm_backend_openai_codex_registration(void)
{
    return &s_openai_codex_registration;
}
