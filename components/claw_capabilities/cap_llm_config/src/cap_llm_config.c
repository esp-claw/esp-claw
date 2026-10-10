/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_llm_config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

#include "cJSON.h"
#include "claw_cap.h"
#include "claw_event_publisher.h"
#include "esp_check.h"
#include "esp_err.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "llm/backends/claw_llm_backend_openai_codex.h"
#include "llm/claw_llm_codex_auth.h"

static const char *TAG = "cap_llm_config";

#define CODEX_LOGIN_TASK_STACK 8192
#define CODEX_API_KEY_MARKER "chatgpt-oauth"

static cap_llm_config_provider_t s_provider;

typedef struct {
    const char *id;
    const char *backend_type;
    const char *base_url;
    const char *auth_type;
    const char *model;
    const char *max_tokens_field;
    const char *default_image_max_bytes;
    const char *supports_tools;
    const char *supports_vision;
    const char *image_remote_url_only;
} cap_llm_preset_t;

typedef struct {
    char provider[CAP_LLM_CONFIG_SHORT_STR_LEN];
    char token[CAP_LLM_CONFIG_STR_LEN];
    char model[CAP_LLM_CONFIG_MODEL_LEN];
    char backend[CAP_LLM_CONFIG_SHORT_STR_LEN];
    char url[CAP_LLM_CONFIG_STR_LEN];
    char base_url[CAP_LLM_CONFIG_STR_LEN];
    char custom_model[CAP_LLM_CONFIG_MODEL_LEN];
    char custom_token[CAP_LLM_CONFIG_STR_LEN];
} cap_llm_config_parse_buf_t;

static const cap_llm_preset_t s_presets[] = {
    {
        .id = "deepseek",
        .backend_type = "openai_compatible",
        .base_url = "https://api.deepseek.com",
        .auth_type = "bearer",
        .model = "deepseek-chat",
        .max_tokens_field = "max_completion_tokens",
        .default_image_max_bytes = "524288",
        .supports_tools = "true",
        .supports_vision = "true",
        .image_remote_url_only = "false",
    },
    {
        .id = "openai",
        .backend_type = "openai_compatible",
        .base_url = "https://api.openai.com/v1",
        .auth_type = "bearer",
        .model = "gpt-4o-mini",
        .max_tokens_field = "max_completion_tokens",
        .default_image_max_bytes = "524288",
        .supports_tools = "true",
        .supports_vision = "true",
        .image_remote_url_only = "false",
    },
    {
        .id = "qwen",
        .backend_type = "openai_compatible",
        .base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1",
        .auth_type = "bearer",
        .model = "qwen-plus",
        .max_tokens_field = "max_tokens",
        .default_image_max_bytes = "524288",
        .supports_tools = "true",
        .supports_vision = "true",
        .image_remote_url_only = "false",
    },
    {
        .id = "anthropic",
        .backend_type = "anthropic_compatible",
        .base_url = "https://api.anthropic.com/v1",
        .auth_type = "none",
        .model = "claude-3-5-haiku-latest",
        .max_tokens_field = "max_tokens",
        .default_image_max_bytes = "524288",
        .supports_tools = "true",
        .supports_vision = "true",
        .image_remote_url_only = "false",
    },
};

/* Applied by /llm codex login on success. The OAuth tokens live in the codex_oauth NVS namespace. */
static const cap_llm_preset_t s_codex_preset = {
    .id = "codex",
    .backend_type = CLAW_LLM_BACKEND_OPENAI_CODEX_ID,
    .base_url = CLAW_LLM_BACKEND_OPENAI_CODEX_BASE_URL,
    .auth_type = "bearer",
    .model = CLAW_LLM_BACKEND_OPENAI_CODEX_DEFAULT_MODEL,
    .max_tokens_field = "max_tokens",
    .default_image_max_bytes = "524288",
    .supports_tools = "true",
    .supports_vision = "true",
    .image_remote_url_only = "false",
};

static const char *s_usage =
    "Usage:\n"
    "/llm status\n"
    "/llm setup deepseek <api_token> [model]\n"
    "/llm setup openai <api_token> [model]\n"
    "/llm setup qwen <api_token> [model]\n"
    "/llm setup anthropic <api_token> [model]\n"
    "/llm setup custom backend=<backend> url=<base_url> model=<model> token=<api_token>\n"
    "/llm codex login\n"
    "/llm codex status\n"
    "/llm codex logout\n"
    "/llm token <api_token>\n"
    "/llm model <model>\n"
    "/llm backend <backend>\n"
    "/llm base-url <base_url>\n"
    "/llm reset\n"
    "Codex login uses your ChatGPT account (backend openai_codex, model "
    CLAW_LLM_BACKEND_OPENAI_CODEX_DEFAULT_MODEL ").\n";

typedef struct {
    claw_llm_codex_device_t device;
    char channel[CAP_LLM_CONFIG_SHORT_STR_LEN];
    char chat_id[CAP_LLM_CONFIG_SHORT_STR_LEN];
} codex_login_t;

static bool is_space(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v';
}

static const char *skip_space(const char *text)
{
    if (!text) {
        return "";
    }
    while (*text && is_space(*text)) {
        text++;
    }
    return text;
}

static esp_err_t read_command_input(const char *input_json, char *command, size_t command_size)
{
    cJSON *root = NULL;
    cJSON *item = NULL;

    if (!command || command_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    command[0] = '\0';
    if (!input_json || !input_json[0]) {
        return ESP_OK;
    }
    root = cJSON_Parse(input_json);
    if (!cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return ESP_ERR_INVALID_ARG;
    }
    item = cJSON_GetObjectItemCaseSensitive(root, "command");
    if (cJSON_IsString(item) && item->valuestring) {
        if (strlcpy(command, item->valuestring, command_size) >= command_size) {
            cJSON_Delete(root);
            return ESP_ERR_INVALID_SIZE;
        }
    }
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t read_token(const char **cursor, char *token, size_t token_size, bool *out_has_token)
{
    const char *start;
    size_t len = 0;

    if (!cursor || !*cursor || !token || token_size == 0 || !out_has_token) {
        return ESP_ERR_INVALID_ARG;
    }
    token[0] = '\0';
    *out_has_token = false;
    start = skip_space(*cursor);
    if (!start[0]) {
        *cursor = start;
        return ESP_OK;
    }
    while (start[len] && !is_space(start[len])) {
        len++;
    }
    if (len >= token_size) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(token, start, len);
    token[len] = '\0';
    *cursor = start + len;
    *out_has_token = true;
    return ESP_OK;
}

static bool find_value_token(const char *command, const char *key, char *value, size_t value_size)
{
    const char *cursor = command;
    size_t key_len = strlen(key);
    char *token = NULL;
    bool has_token = false;
    bool found = false;

    if (!value || value_size == 0) {
        return false;
    }
    value[0] = '\0';
    token = calloc(1, CAP_LLM_CONFIG_STR_LEN);
    if (!token) {
        return false;
    }
    while (read_token(&cursor, token, CAP_LLM_CONFIG_STR_LEN, &has_token) == ESP_OK && has_token) {
        if (strncmp(token, key, key_len) == 0 && token[key_len] == '=') {
            strlcpy(value, token + key_len + 1, value_size);
            found = true;
            break;
        }
    }
    free(token);
    return found;
}

static const cap_llm_preset_t *find_preset(const char *id)
{
    for (size_t i = 0; i < sizeof(s_presets) / sizeof(s_presets[0]); i++) {
        if (strcmp(s_presets[i].id, id) == 0) {
            return &s_presets[i];
        }
    }
    return NULL;
}

static void mask_token(const char *token, char *out, size_t out_size)
{
    size_t len;

    if (!out || out_size == 0) {
        return;
    }
    if (!token || !token[0]) {
        strlcpy(out, "(missing)", out_size);
        return;
    }
    len = strlen(token);
    if (len <= 8) {
        strlcpy(out, "configured", out_size);
        return;
    }
    snprintf(out, out_size, "%.4s...%s", token, token + len - 4);
}

static void apply_preset(cap_llm_config_t *config, const cap_llm_preset_t *preset)
{
    strlcpy(config->backend_type, preset->backend_type, sizeof(config->backend_type));
    strlcpy(config->base_url, preset->base_url, sizeof(config->base_url));
    strlcpy(config->auth_type, preset->auth_type, sizeof(config->auth_type));
    strlcpy(config->model, preset->model, sizeof(config->model));
    strlcpy(config->max_tokens_field, preset->max_tokens_field, sizeof(config->max_tokens_field));
    strlcpy(config->default_image_max_bytes,
            preset->default_image_max_bytes,
            sizeof(config->default_image_max_bytes));
    strlcpy(config->supports_tools, preset->supports_tools, sizeof(config->supports_tools));
    strlcpy(config->supports_vision, preset->supports_vision, sizeof(config->supports_vision));
    strlcpy(config->image_remote_url_only,
            preset->image_remote_url_only,
            sizeof(config->image_remote_url_only));
}

static bool command_has_sensitive_token(const char *subcommand, const char *command)
{
    char *value = NULL;
    bool found = false;

    if (strcmp(subcommand, "token") == 0 || strcmp(subcommand, "setup") == 0) {
        return true;
    }

    value = calloc(1, CAP_LLM_CONFIG_STR_LEN);
    if (!value) {
        return false;
    }
    found = find_value_token(command, "token", value, CAP_LLM_CONFIG_STR_LEN) ||
            find_value_token(command, "key", value, CAP_LLM_CONFIG_STR_LEN) ||
            find_value_token(command, "api_key", value, CAP_LLM_CONFIG_STR_LEN) ||
            find_value_token(command, "api-token", value, CAP_LLM_CONFIG_STR_LEN);
    free(value);
    return found;
}

static bool context_is_obvious_group_chat(const claw_cap_call_context_t *ctx)
{
    const char *chat_id = ctx ? ctx->chat_id : NULL;

    if (!chat_id || !chat_id[0]) {
        return false;
    }
    return strstr(chat_id, "group") != NULL ||
           strstr(chat_id, "room") != NULL ||
           strstr(chat_id, "guild") != NULL;
}

static void write_status(const cap_llm_config_t *config, char *output, size_t output_size)
{
    char masked[32];

    mask_token(config->api_key, masked, sizeof(masked));
    snprintf(output,
             output_size,
             "LLM status\n"
             "backend: %s\n"
             "base_url: %s\n"
             "model: %s\n"
             "token: %s\n"
             "tools: %s vision: %s",
             config->backend_type[0] ? config->backend_type : "(missing)",
             config->base_url[0] ? config->base_url : "(missing)",
             config->model[0] ? config->model : "(missing)",
             masked,
             config->supports_tools[0] ? config->supports_tools : "false",
             config->supports_vision[0] ? config->supports_vision : "false");
}

static bool config_ready(const cap_llm_config_t *config)
{
    return config->api_key[0] &&
           config->backend_type[0] &&
           config->base_url[0] &&
           config->model[0];
}

static esp_err_t save_config(cap_llm_config_t *config, char *output, size_t output_size)
{
    esp_err_t err;

    if (!s_provider.apply_config) {
        snprintf(output, output_size, "LLM config save failed: provider is not configured.");
        return ESP_ERR_INVALID_STATE;
    }

    err = s_provider.apply_config(config, s_provider.user_ctx);

    if (err != ESP_OK) {
        snprintf(output, output_size, "LLM config save failed: %s", esp_err_to_name(err));
        return err;
    }
    snprintf(output,
             output_size,
             "LLM config saved. %s",
             config_ready(config) ?
             "The next message will use this model." :
             "Some required fields are still missing; run /llm status.");
    return ESP_OK;
}

static esp_err_t save_codex_login_config(void)
{
    cap_llm_config_t *config = calloc(1, sizeof(*config));
    esp_err_t err = ESP_ERR_NO_MEM;

    if (!config) {
        return err;
    }
    err = s_provider.get_config(config, s_provider.user_ctx);
    if (err == ESP_OK) {
        apply_preset(config, &s_codex_preset);
        strlcpy(config->api_key, CODEX_API_KEY_MARKER, sizeof(config->api_key));
        err = s_provider.apply_config(config, s_provider.user_ctx);
    }
    free(config);
    return err;
}

static void codex_login_task(void *arg)
{
    codex_login_t *login = arg;
    char *error = NULL;
    char message[256];
    esp_err_t err = claw_llm_codex_device_wait(&login->device, &error);

    if (err == ESP_OK) {
        err = save_codex_login_config();
    }
    if (err == ESP_OK) {
        snprintf(message,
                 sizeof(message),
                 "Codex login complete. Backend is now %s (model %s).",
                 CLAW_LLM_BACKEND_OPENAI_CODEX_ID,
                 CLAW_LLM_BACKEND_OPENAI_CODEX_DEFAULT_MODEL);
    } else {
        snprintf(message, sizeof(message), "Codex login failed: %s", error ? error : esp_err_to_name(err));
    }
    ESP_LOGI(TAG, "%s", message);
    if (login->chat_id[0]) {
        claw_event_router_publish_message("llm_config", login->channel, login->chat_id, message, "system", NULL);
    }
    free(error);
    claw_llm_codex_device_free(&login->device);
    free(login);
    vTaskDelete(NULL);
}

static esp_err_t start_codex_login(const claw_cap_call_context_t *ctx, char *output, size_t output_size)
{
    codex_login_t *login = calloc(1, sizeof(*login));
    char *error = NULL;
    esp_err_t err;

    if (!login) {
        snprintf(output, output_size, "Codex login failed: out of memory.");
        return ESP_ERR_NO_MEM;
    }
    err = claw_llm_codex_device_start(&login->device, &error);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Codex login failed: %s", error ? error : esp_err_to_name(err));
        free(error);
        free(login);
        return err;
    }
    if (ctx && ctx->channel) {
        strlcpy(login->channel, ctx->channel, sizeof(login->channel));
    }
    if (ctx && ctx->chat_id) {
        strlcpy(login->chat_id, ctx->chat_id, sizeof(login->chat_id));
    }
    /* Build the reply before the task starts; the task frees the device code. */
    snprintf(output,
             output_size,
             "Open https://auth.openai.com/codex/device and enter the code %s.\n"
             "I will report here when sign-in finishes (15 minute limit).",
             login->device.user_code);
    if (xTaskCreate(codex_login_task, "codex_login", CODEX_LOGIN_TASK_STACK, login, 5, NULL) != pdPASS) {
        snprintf(output, output_size, "Codex login failed: could not start the login task.");
        claw_llm_codex_device_free(&login->device);
        free(login);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void write_codex_status(char *output, size_t output_size)
{
    int64_t expires_at = 0;
    bool logged_in = claw_llm_codex_is_logged_in(&expires_at);
    char expiry[32] = "n/a";

    if (logged_in) {
        time_t when = (time_t)expires_at;
        struct tm utc;

        if (expires_at > 0 && gmtime_r(&when, &utc)) {
            strftime(expiry, sizeof(expiry), "%Y-%m-%d %H:%M UTC", &utc);
        } else {
            strlcpy(expiry, "unknown", sizeof(expiry));
        }
    }
    snprintf(output,
             output_size,
             "Codex login: %s\nAccess token expires: %s",
             logged_in ? "yes" : "no",
             expiry);
}

static esp_err_t llm_config_execute(const char *input_json,
                                    const claw_cap_call_context_t *ctx,
                                    char *output,
                                    size_t output_size)
{
    cap_llm_config_t *config = NULL;
    cap_llm_config_parse_buf_t *parse_buf = NULL;
    char *command = NULL;
    const char *cursor = NULL;
    char subcommand[32];
    bool has_subcommand = false;
    esp_err_t err = ESP_OK;

    if (!output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    output[0] = '\0';

    config = calloc(1, sizeof(*config));
    parse_buf = calloc(1, sizeof(*parse_buf));
    command = calloc(1, 512);
    if (!config || !parse_buf || !command) {
        err = ESP_ERR_NO_MEM;
        snprintf(output, output_size, "LLM command failed: out of memory.");
        goto cleanup;
    }

    err = read_command_input(input_json, command, 512);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Invalid /llm command input.");
        goto cleanup;
    }
    cursor = command;
    err = read_token(&cursor, subcommand, sizeof(subcommand), &has_subcommand);
    if (err != ESP_OK || !has_subcommand ||
            strcmp(subcommand, "help") == 0 || strcmp(subcommand, "?") == 0) {
        strlcpy(output, s_usage, output_size);
        err = ESP_OK;
        goto cleanup;
    }

    if (!s_provider.get_config) {
        snprintf(output, output_size, "LLM config is not ready: provider is not configured.");
        err = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    err = s_provider.get_config(config, s_provider.user_ctx);
    if (err != ESP_OK) {
        snprintf(output, output_size, "LLM config is not ready: %s", esp_err_to_name(err));
        goto cleanup;
    }

    if (strcmp(subcommand, "status") == 0 || strcmp(subcommand, "show") == 0) {
        write_status(config, output, output_size);
        err = ESP_OK;
        goto cleanup;
    }

    if (strcmp(subcommand, "codex") == 0) {
        char action[32];
        bool has_action = false;

        err = read_token(&cursor, action, sizeof(action), &has_action);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "codex action parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (has_action && strcmp(action, "login") == 0) {
            err = start_codex_login(ctx, output, output_size);
        } else if (has_action && strcmp(action, "status") == 0) {
            write_codex_status(output, output_size);
            err = ESP_OK;
        } else if (has_action && strcmp(action, "logout") == 0) {
            err = claw_llm_codex_logout();
            snprintf(output,
                     output_size,
                     "%s",
                     err == ESP_OK ? "Codex login removed." : "Codex logout failed.");
        } else {
            strlcpy(output, s_usage, output_size);
            err = ESP_OK;
        }
        goto cleanup;
    }

    if (command_has_sensitive_token(subcommand, command) && context_is_obvious_group_chat(ctx)) {
        strlcpy(output,
                "For safety, configure API tokens in a private chat, Web IM, or the device settings page.",
                output_size);
        err = ESP_OK;
        goto cleanup;
    }

    if (strcmp(subcommand, "setup") == 0) {
        bool has_provider = false;
        bool has_token = false;
        bool has_model = false;

        err = read_token(&cursor, parse_buf->provider, sizeof(parse_buf->provider), &has_provider);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "setup provider parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_provider) {
            strlcpy(output, s_usage, output_size);
            err = ESP_OK;
            goto cleanup;
        }
        if (strcmp(parse_buf->provider, "custom") == 0) {
            bool has_backend = find_value_token(command,
                                                "backend",
                                                parse_buf->backend,
                                                sizeof(parse_buf->backend));
            bool has_url = find_value_token(command, "url", parse_buf->url, sizeof(parse_buf->url));
            bool has_base_url = find_value_token(command,
                                                 "base_url",
                                                 parse_buf->base_url,
                                                 sizeof(parse_buf->base_url));
            bool has_model = find_value_token(command,
                                              "model",
                                              parse_buf->custom_model,
                                              sizeof(parse_buf->custom_model));
            bool has_token = find_value_token(command,
                                              "token",
                                              parse_buf->custom_token,
                                              sizeof(parse_buf->custom_token));

            if (!has_token) {
                has_token = find_value_token(command,
                                             "key",
                                             parse_buf->custom_token,
                                             sizeof(parse_buf->custom_token));
            }
            if (!has_token) {
                has_token = find_value_token(command,
                                             "api_key",
                                             parse_buf->custom_token,
                                             sizeof(parse_buf->custom_token));
            }
            if (!has_token) {
                has_token = find_value_token(command,
                                             "api-token",
                                             parse_buf->custom_token,
                                             sizeof(parse_buf->custom_token));
            }
            if (!has_backend || !(has_url || has_base_url) || !has_model || !has_token) {
                strlcpy(output,
                        "Usage: /llm setup custom backend=<backend> url=<base_url> model=<model> token=<api_token>",
                        output_size);
                err = ESP_OK;
                goto cleanup;
            }
            strlcpy(config->backend_type, parse_buf->backend, sizeof(config->backend_type));
            strlcpy(config->base_url,
                    has_url ? parse_buf->url : parse_buf->base_url,
                    sizeof(config->base_url));
            strlcpy(config->model, parse_buf->custom_model, sizeof(config->model));
            strlcpy(config->api_key, parse_buf->custom_token, sizeof(config->api_key));
            if (!config->auth_type[0]) {
                strlcpy(config->auth_type, "bearer", sizeof(config->auth_type));
            }
            if (!config->max_tokens_field[0]) {
                strlcpy(config->max_tokens_field, "max_tokens", sizeof(config->max_tokens_field));
            }
            if (!config->default_image_max_bytes[0]) {
                strlcpy(config->default_image_max_bytes, "524288",
                        sizeof(config->default_image_max_bytes));
            }
            err = save_config(config, output, output_size);
            goto cleanup;
        }

        const cap_llm_preset_t *preset = find_preset(parse_buf->provider);
        if (!preset) {
            snprintf(output,
                     output_size,
                     "Unknown LLM provider: %s\n\n%s",
                     parse_buf->provider,
                     s_usage);
            err = ESP_OK;
            goto cleanup;
        }
        err = read_token(&cursor, parse_buf->token, sizeof(parse_buf->token), &has_token);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "setup token parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        err = read_token(&cursor, parse_buf->model, sizeof(parse_buf->model), &has_model);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "setup model parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_token) {
            snprintf(output, output_size, "Missing API token.\n\n%s", s_usage);
            err = ESP_OK;
            goto cleanup;
        }
        apply_preset(config, preset);
        strlcpy(config->api_key, parse_buf->token, sizeof(config->api_key));
        if (has_model) {
            strlcpy(config->model, parse_buf->model, sizeof(config->model));
        }
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    if (strcmp(subcommand, "token") == 0) {
        bool has_token = false;

        err = read_token(&cursor, parse_buf->token, sizeof(parse_buf->token), &has_token);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "token parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_token) {
            strlcpy(output, "Usage: /llm token <api_token>", output_size);
            err = ESP_OK;
            goto cleanup;
        }
        strlcpy(config->api_key, parse_buf->token, sizeof(config->api_key));
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    if (strcmp(subcommand, "model") == 0) {
        bool has_model = false;

        err = read_token(&cursor, parse_buf->model, sizeof(parse_buf->model), &has_model);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "model parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_model) {
            strlcpy(output, "Usage: /llm model <model>", output_size);
            err = ESP_OK;
            goto cleanup;
        }
        strlcpy(config->model, parse_buf->model, sizeof(config->model));
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    if (strcmp(subcommand, "backend") == 0) {
        bool has_backend = false;

        err = read_token(&cursor, parse_buf->backend, sizeof(parse_buf->backend), &has_backend);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "backend parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_backend) {
            strlcpy(output,
                    "Usage: /llm backend <openai_compatible|anthropic_compatible|openai_codex>",
                    output_size);
            err = ESP_OK;
            goto cleanup;
        }
        strlcpy(config->backend_type, parse_buf->backend, sizeof(config->backend_type));
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    if (strcmp(subcommand, "base-url") == 0 || strcmp(subcommand, "url") == 0) {
        bool has_url = false;

        err = read_token(&cursor, parse_buf->url, sizeof(parse_buf->url), &has_url);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "base-url parse failed: %s", esp_err_to_name(err));
            goto cleanup;
        }
        if (!has_url) {
            strlcpy(output, "Usage: /llm base-url <base_url>", output_size);
            err = ESP_OK;
            goto cleanup;
        }
        strlcpy(config->base_url, parse_buf->url, sizeof(config->base_url));
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    if (strcmp(subcommand, "test") == 0) {
        snprintf(output,
                 output_size,
                 "%s",
                 config_ready(config) ?
                 "LLM config has all required fields. Send a normal message to test the model." :
                 "LLM config is incomplete. Run /llm status.");
        err = ESP_OK;
        goto cleanup;
    }

    if (strcmp(subcommand, "reset") == 0) {
        config->api_key[0] = '\0';
        config->backend_type[0] = '\0';
        config->model[0] = '\0';
        config->base_url[0] = '\0';
        config->auth_type[0] = '\0';
        config->max_tokens_field[0] = '\0';
        config->supports_tools[0] = '\0';
        config->supports_vision[0] = '\0';
        config->image_remote_url_only[0] = '\0';
        err = save_config(config, output, output_size);
        goto cleanup;
    }

    strlcpy(output, s_usage, output_size);
    err = ESP_OK;

cleanup:
    free(command);
    free(parse_buf);
    free(config);
    return err;
}

static const claw_cap_descriptor_t s_llm_config_caps[] = {
    {
        .id = "llm_config_command",
        .name = "llm_config_command",
        .family = "app",
        .description = "Handle /llm configuration commands.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = llm_config_execute,
    },
};

static const claw_cap_group_t s_llm_config_group = {
    .group_id = "cap_llm_config",
    .plugin_name = "cap_llm_config",
    .version = "1.0.0",
    .descriptors = s_llm_config_caps,
    .descriptor_count = sizeof(s_llm_config_caps) / sizeof(s_llm_config_caps[0]),
};

esp_err_t cap_llm_config_set_provider(const cap_llm_config_provider_t *provider)
{
    if (!provider || !provider->get_config || !provider->apply_config) {
        return ESP_ERR_INVALID_ARG;
    }

    s_provider = *provider;
    return ESP_OK;
}

esp_err_t cap_llm_config_register_group(void)
{
    if (!s_provider.get_config || !s_provider.apply_config) {
        return ESP_ERR_INVALID_STATE;
    }
    if (claw_cap_group_exists(s_llm_config_group.group_id)) {
        return ESP_OK;
    }

    return claw_cap_register_group(&s_llm_config_group);
}
