/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_ssh.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cap_im_tg.h"
#include "claw_cap.h"
#include "claw_task.h"
#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "libssh/libssh.h"
#include "mbedtls/base64.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"

static const char *TAG = "cap_ssh";

#define CAP_SSH_HOSTS_MAX          1536
#define CAP_SSH_DESCRIPTION_MAX    384
#define CAP_SSH_PUBKEY_MAX         160
#define CAP_SSH_COMMAND_MAX        1024
#define CAP_SSH_OUTPUT_MAX         (8 * 1024)
#define CAP_SSH_PROMPT_MAX         4096
#define CAP_SSH_STATUS_RESERVE     96
#define CAP_SSH_CONFIRM_TIMEOUT_MS 60000
#define CAP_SSH_CONNECT_TIMEOUT_S  10
#define CAP_SSH_TOTAL_TIMEOUT_MS   30000
#define CAP_SSH_READ_SLICE_MS      200
#define CAP_SSH_NVS_NAMESPACE      "ssh_client"
#define CAP_SSH_NVS_KEY            "privkey"
#define CAP_SSH_KEY_COMMENT        "esp-claw"
#define CAP_SSH_HOSTKEY_ALGOS      "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"

typedef struct {
    char host[128];
    char user[64];
    char fingerprints[256];
    unsigned int port;
    const char *command;
    char *out;
    char *err;
    size_t out_len;
    size_t err_len;
    bool truncated;
    bool timed_out;
    int exit_code;
    char error[192];
    SemaphoreHandle_t done;
} cap_ssh_job_t;

typedef struct {
    char hosts_json[CAP_SSH_HOSTS_MAX];
    char description[CAP_SSH_DESCRIPTION_MAX];
    char pubkey[CAP_SSH_PUBKEY_MAX];
    ssh_key key;
    volatile bool key_ready;
    QueueHandle_t queue;
    TaskHandle_t worker;
} cap_ssh_state_t;

static EXT_RAM_BSS_ATTR cap_ssh_state_t s_ssh;

static void cap_ssh_init_key(void)
{
    nvs_handle_t nvs;
    ssh_key key = NULL;
    char *b64 = NULL;
    char *pub = NULL;
    size_t len = 0;
    bool generated = false;
    esp_err_t err;

    err = nvs_open(CAP_SSH_NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open NVS namespace %s: %s", CAP_SSH_NVS_NAMESPACE, esp_err_to_name(err));
        return;
    }

    if (nvs_get_str(nvs, CAP_SSH_NVS_KEY, NULL, &len) == ESP_OK && len > 0) {
        b64 = calloc(1, len);
        if (b64 && nvs_get_str(nvs, CAP_SSH_NVS_KEY, b64, &len) == ESP_OK &&
                ssh_pki_import_privkey_base64(b64, NULL, NULL, NULL, &key) != SSH_OK) {
            ESP_LOGW(TAG, "Stored SSH client key is unreadable, generating a new one");
            key = NULL;
        }
        if (b64) {
            mbedtls_platform_zeroize(b64, len);
            free(b64);
            b64 = NULL;
        }
    }

    if (!key) {
        if (ssh_pki_generate_key(SSH_KEYTYPE_ED25519, NULL, &key) != SSH_OK ||
                ssh_pki_export_privkey_base64(key, NULL, NULL, NULL, &b64) != SSH_OK) {
            ESP_LOGE(TAG, "Failed to generate SSH client key");
            ssh_key_free(key);
            nvs_close(nvs);
            return;
        }
        err = nvs_set_str(nvs, CAP_SSH_NVS_KEY, b64);
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
        }
        mbedtls_platform_zeroize(b64, strlen(b64));
        ssh_string_free_char(b64);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to store SSH client key: %s", esp_err_to_name(err));
            ssh_key_free(key);
            nvs_close(nvs);
            return;
        }
        generated = true;
    }
    nvs_close(nvs);

    if (ssh_pki_export_pubkey_base64(key, &pub) != SSH_OK) {
        ESP_LOGE(TAG, "Failed to export SSH public key");
        ssh_key_free(key);
        return;
    }
    snprintf(s_ssh.pubkey, sizeof(s_ssh.pubkey), "%s %s " CAP_SSH_KEY_COMMENT,
             ssh_key_type_to_char(ssh_key_type(key)), pub);
    ssh_string_free_char(pub);
    s_ssh.key = key;
    s_ssh.key_ready = true;
    ESP_LOGI(TAG, "SSH client public key%s: %s", generated ? " (new)" : "", s_ssh.pubkey);
}

static bool cap_ssh_fingerprint_listed(const char *list, const char *fingerprint)
{
    size_t fp_len = strlen(fingerprint);

    while (*list) {
        size_t len;

        while (*list == ',' || *list == ' ') {
            list++;
        }
        len = strcspn(list, ", ");
        if (len == fp_len && strncmp(list, fingerprint, len) == 0) {
            return true;
        }
        list += len;
    }
    return false;
}

static bool cap_ssh_hostkey_matches(ssh_session session, cap_ssh_job_t *job)
{
    ssh_key key = NULL;
    unsigned char *hash = NULL;
    size_t hash_len = 0;
    size_t b64_len = 0;
    char fingerprint[64] = "SHA256:";
    const size_t prefix_len = strlen(fingerprint);
    bool ok = false;

    if (ssh_get_server_publickey(session, &key) != SSH_OK ||
            ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hash_len) != SSH_OK) {
        snprintf(job->error, sizeof(job->error), "could not read the server host key");
        ssh_key_free(key);
        return false;
    }

    if (mbedtls_base64_encode((unsigned char *)fingerprint + prefix_len, sizeof(fingerprint) - prefix_len,
                              &b64_len, hash, hash_len) == 0) {
        /* OpenSSH prints SHA256 fingerprints without base64 padding. */
        while (b64_len > 0 && fingerprint[prefix_len + b64_len - 1] == '=') {
            b64_len--;
        }
        fingerprint[prefix_len + b64_len] = '\0';
        ok = cap_ssh_fingerprint_listed(job->fingerprints, fingerprint);
    }
    if (!ok) {
        snprintf(job->error, sizeof(job->error), "host key %s %s does not match the pinned fingerprint",
                 ssh_key_type_to_char(ssh_key_type(key)), fingerprint);
    }

    ssh_clean_pubkey_hash(&hash);
    ssh_key_free(key);
    return ok;
}

static void cap_ssh_capture(cap_ssh_job_t *job, char *dst, size_t *dst_len, const char *data, int len)
{
    size_t room = CAP_SSH_OUTPUT_MAX - job->out_len - job->err_len;
    size_t take = (size_t)len < room ? (size_t)len : room;

    memcpy(dst + *dst_len, data, take);
    *dst_len += take;
    dst[*dst_len] = '\0';
    if (take < (size_t)len) {
        job->truncated = true;
    }
}

static void cap_ssh_read_output(ssh_session session, ssh_channel channel, cap_ssh_job_t *job, int64_t deadline_us)
{
    char buf[512];
    uint32_t exit_code = 0;
    int n;
    int n2;

    while (!ssh_channel_is_eof(channel)) {
        if (esp_timer_get_time() >= deadline_us) {
            job->timed_out = true;
            return;
        }
        n = ssh_channel_read_timeout(channel, buf, sizeof(buf), 0, CAP_SSH_READ_SLICE_MS);
        if (n > 0) {
            cap_ssh_capture(job, job->out, &job->out_len, buf, n);
        }
        if (n == SSH_ERROR) {
            snprintf(job->error, sizeof(job->error), "read failed: %s", ssh_get_error(session));
            return;
        }
        while ((n2 = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 1)) > 0) {
            cap_ssh_capture(job, job->err, &job->err_len, buf, n2);
        }
        if (n == 0 && !ssh_channel_is_open(channel)) {
            break;
        }
    }

    if (ssh_channel_get_exit_state(channel, &exit_code, NULL, NULL) == SSH_OK) {
        job->exit_code = (int)exit_code;
    }
}

static void cap_ssh_run(cap_ssh_job_t *job)
{
    ssh_session session = NULL;
    ssh_channel channel = NULL;
    long timeout_s = CAP_SSH_CONNECT_TIMEOUT_S;
    bool process_config = false;
    int64_t deadline_us = esp_timer_get_time() + (int64_t)CAP_SSH_TOTAL_TIMEOUT_MS * 1000;

    session = ssh_new();
    if (!session) {
        snprintf(job->error, sizeof(job->error), "out of memory");
        return;
    }
    /* SSH_DIR is set so libssh never needs a home directory, which ESP-IDF does not have. */
    if (ssh_options_set(session, SSH_OPTIONS_HOST, job->host) != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_PORT, &job->port) != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_USER, job->user) != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout_s) != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config) != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_SSH_DIR, "/ssh") != SSH_OK ||
            ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, CAP_SSH_HOSTKEY_ALGOS) != SSH_OK) {
        snprintf(job->error, sizeof(job->error), "invalid session options: %s", ssh_get_error(session));
        goto done;
    }
    if (ssh_connect(session) != SSH_OK) {
        snprintf(job->error, sizeof(job->error), "connect failed: %s", ssh_get_error(session));
        goto done;
    }
    if (!cap_ssh_hostkey_matches(session, job)) {
        goto done;
    }
    if (ssh_userauth_publickey(session, NULL, s_ssh.key) != SSH_AUTH_SUCCESS) {
        snprintf(job->error, sizeof(job->error),
                 "public key authentication failed; add the key from /ssh pubkey to authorized_keys");
        goto done;
    }
    channel = ssh_channel_new(session);
    if (!channel || ssh_channel_open_session(channel) != SSH_OK ||
            ssh_channel_request_exec(channel, job->command) != SSH_OK) {
        snprintf(job->error, sizeof(job->error), "exec failed: %s", ssh_get_error(session));
        goto done;
    }
    cap_ssh_read_output(session, channel, job, deadline_us);

done:
    if (channel) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }
    ssh_disconnect(session);
    ssh_free(session);
}

static void cap_ssh_worker_task(void *arg)
{
    cap_ssh_job_t *job = NULL;

    (void)arg;
    if (ssh_init() != SSH_OK) {
        ESP_LOGE(TAG, "libssh init failed");
    } else {
        cap_ssh_init_key();
    }

    while (xQueueReceive(s_ssh.queue, &job, portMAX_DELAY) == pdTRUE) {
        if (s_ssh.key_ready) {
            cap_ssh_run(job);
        } else {
            snprintf(job->error, sizeof(job->error), "SSH client key is not available");
        }
        ESP_LOGI(TAG, "ssh_exec %s@%s done exit=%d err=%s internal_free=%u",
                 job->user, job->host, job->exit_code, job->error[0] ? job->error : "none",
                 (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        xSemaphoreGive(job->done);
    }
}

/* Appends `text`, HTML-escaped when `escape` is set; fails when the prompt would leave no
 * room for the status line added after the user answers. */
static bool cap_ssh_html_put(char *html, size_t *len, const char *text, bool escape)
{
    for (; *text; text++) {
        const char *entity = !escape ? NULL :
                             *text == '&' ? "&amp;" :
                             *text == '<' ? "&lt;" :
                             *text == '>' ? "&gt;" : NULL;
        size_t n = entity ? strlen(entity) : 1;

        if (*len + n >= CAP_SSH_PROMPT_MAX - CAP_SSH_STATUS_RESERVE) {
            return false;
        }
        memcpy(html + *len, entity ? entity : text, n);
        *len += n;
    }
    html[*len] = '\0';
    return true;
}

static void cap_ssh_finish_prompt(const char *chat_id, int64_t message_id, char *html, size_t prompt_len,
                                  const char *status)
{
    snprintf(html + prompt_len, CAP_SSH_PROMPT_MAX - prompt_len, "\n\n<b>%s</b>", status);
    if (cap_im_tg_edit_message(chat_id, message_id, html) != ESP_OK) {
        ESP_LOGW(TAG, "Failed to update confirmation message");
    }
}

/* Copies the named host entry from the configured hosts into the job. */
static bool cap_ssh_lookup_host(const char *name, cap_ssh_job_t *job, char *output, size_t output_size)
{
    cJSON *hosts = cJSON_Parse(s_ssh.hosts_json);
    cJSON *entry = NULL;
    bool found = false;

    cJSON_ArrayForEach(entry, (cJSON_IsArray(hosts) ? hosts : NULL)) {
        const char *entry_name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));
        const char *host = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "host"));
        const char *user = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "user"));
        const char *fingerprint = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "fingerprint"));
        cJSON *port = cJSON_GetObjectItem(entry, "port");

        if (!entry_name || strcmp(entry_name, name) != 0) {
            continue;
        }
        found = true;
        if (!host || !host[0] || !user || !user[0]) {
            snprintf(output, output_size, "Error: ssh host '%s' needs host and user", name);
            break;
        }
        if (!fingerprint || strncmp(fingerprint, "SHA256:", 7) != 0) {
            snprintf(output, output_size,
                     "Error: ssh host '%s' has no pinned SHA256 host key fingerprint; refusing to connect", name);
            break;
        }
        strlcpy(job->host, host, sizeof(job->host));
        strlcpy(job->user, user, sizeof(job->user));
        strlcpy(job->fingerprints, fingerprint, sizeof(job->fingerprints));
        job->port = cJSON_IsNumber(port) && port->valueint > 0 && port->valueint < 65536 ? (unsigned int)port->valueint : 22;
        cJSON_Delete(hosts);
        return true;
    }

    if (!found) {
        snprintf(output, output_size, "Error: unknown ssh host '%s'", name);
    }
    cJSON_Delete(hosts);
    return false;
}

static void cap_ssh_write_result(const char *name, const cap_ssh_job_t *job, char *output, size_t output_size)
{
    cJSON *root = cJSON_CreateObject();
    char *rendered = NULL;

    if (root) {
        cJSON_AddStringToObject(root, "host", name);
        cJSON_AddNumberToObject(root, "exit_code", job->exit_code);
        cJSON_AddStringToObject(root, "stdout", job->out);
        cJSON_AddStringToObject(root, "stderr", job->err);
        cJSON_AddBoolToObject(root, "truncated", job->truncated);
        if (job->timed_out) {
            cJSON_AddBoolToObject(root, "timed_out", true);
        }
        rendered = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }
    snprintf(output, output_size, "%s", rendered ? rendered : "Error: out of memory");
    free(rendered);
}

static esp_err_t cap_ssh_exec_execute(const char *input_json,
                                      const claw_cap_call_context_t *ctx,
                                      char *output,
                                      size_t output_size)
{
    cJSON *input = NULL;
    const char *name = NULL;
    const char *command = NULL;
    cap_ssh_job_t *job = NULL;
    char *html = NULL;
    size_t prompt_len = 0;
    char port[8];
    char status[48];
    int64_t message_id = 0;
    cap_im_tg_confirm_result_t answer = CAP_IM_TG_CONFIRM_TIMEOUT;
    esp_err_t err;

    /* Confirmation is only possible in the Telegram chat the request came from. */
    if (!ctx || ctx->caller != CLAW_CAP_CALLER_AGENT || !ctx->channel || strcmp(ctx->channel, "telegram") != 0 ||
            !ctx->source_cap || strcmp(ctx->source_cap, "tg_gateway") != 0 || !ctx->chat_id || !ctx->chat_id[0]) {
        snprintf(output, output_size,
                 "Error: ssh_exec is only available for requests from an allowed Telegram chat");
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!s_ssh.key_ready) {
        snprintf(output, output_size, "Error: SSH client key is not available");
        return ESP_ERR_INVALID_STATE;
    }

    input = cJSON_Parse(input_json);
    name = cJSON_GetStringValue(cJSON_GetObjectItem(input, "host"));
    command = cJSON_GetStringValue(cJSON_GetObjectItem(input, "command"));
    if (!name || !name[0] || !command || !command[0]) {
        cJSON_Delete(input);
        snprintf(output, output_size, "Error: host and command are required");
        return ESP_ERR_INVALID_ARG;
    }
    if (strlen(command) > CAP_SSH_COMMAND_MAX) {
        cJSON_Delete(input);
        snprintf(output, output_size, "Error: command longer than %d bytes", CAP_SSH_COMMAND_MAX);
        return ESP_ERR_INVALID_ARG;
    }

    job = calloc(1, sizeof(*job));
    html = heap_caps_malloc(CAP_SSH_PROMPT_MAX, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!job || !html) {
        err = ESP_ERR_NO_MEM;
        snprintf(output, output_size, "Error: out of memory");
        goto cleanup;
    }
    if (!cap_ssh_lookup_host(name, job, output, output_size)) {
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }
    job->command = command;
    job->exit_code = -1;

    snprintf(port, sizeof(port), "%u", job->port);
    {
        /* Odd entries are config or LLM data and get escaped. */
        const char *parts[] = {
            "<b>SSH-Befehl bestätigen</b>\nHost: <b>", name, "</b> (", job->user, "@", job->host,
            ":", port, ")\n<pre>", command, "</pre>",
        };

        for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); i++) {
            if (!cap_ssh_html_put(html, &prompt_len, parts[i], i % 2 == 1)) {
                err = ESP_ERR_INVALID_SIZE;
                snprintf(output, output_size, "Error: command too long to show for confirmation");
                goto cleanup;
            }
        }
    }

    err = cap_im_tg_confirm(ctx->chat_id, html, CAP_SSH_CONFIRM_TIMEOUT_MS, &answer, &message_id);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: could not ask for confirmation in Telegram (%s)", esp_err_to_name(err));
        goto cleanup;
    }
    if (answer != CAP_IM_TG_CONFIRM_APPROVED) {
        bool timeout = answer == CAP_IM_TG_CONFIRM_TIMEOUT;

        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len,
                              timeout ? "⌛ Zeitüberschreitung" : "❌ abgelehnt");
        snprintf(output, output_size, "Error: %s",
                 timeout ? "Zeitüberschreitung: keine Bestätigung innerhalb von 60 s" : "abgelehnt vom Benutzer");
        err = timeout ? ESP_ERR_TIMEOUT : ESP_FAIL;
        goto cleanup;
    }

    job->out = heap_caps_calloc(1, CAP_SSH_OUTPUT_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    job->err = heap_caps_calloc(1, CAP_SSH_OUTPUT_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    job->done = xSemaphoreCreateBinary();
    if (!job->out || !job->err || !job->done || xQueueSend(s_ssh.queue, &job, 0) != pdTRUE) {
        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, "⚠️ fehlgeschlagen");
        err = ESP_ERR_NO_MEM;
        snprintf(output, output_size, "Error: could not start the SSH session");
        goto cleanup;
    }
    /* The worker bounds every step with its own timeouts. */
    xSemaphoreTake(job->done, portMAX_DELAY);

    if (job->error[0]) {
        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, "⚠️ fehlgeschlagen");
        snprintf(output, output_size, "Error: ssh %s: %s", name, job->error);
        err = ESP_FAIL;
        goto cleanup;
    }
    if (job->timed_out) {
        strlcpy(status, "⌛ abgebrochen nach 30 s", sizeof(status));
    } else {
        snprintf(status, sizeof(status), "✅ ausgeführt (exit %d)", job->exit_code);
    }
    cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, status);
    cap_ssh_write_result(name, job, output, output_size);
    err = ESP_OK;

cleanup:
    if (job) {
        if (job->done) {
            vSemaphoreDelete(job->done);
        }
        free(job->out);
        free(job->err);
        free(job);
    }
    free(html);
    cJSON_Delete(input);
    return err;
}

static esp_err_t cap_ssh_command_execute(const char *input_json,
                                         const claw_cap_call_context_t *ctx,
                                         char *output,
                                         size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    const char *command = cJSON_GetStringValue(cJSON_GetObjectItem(input, "command"));

    (void)ctx;
    if (command && strcmp(command, "pubkey") == 0) {
        if (s_ssh.key_ready) {
            snprintf(output, output_size, "`%s`", s_ssh.pubkey);
        } else {
            snprintf(output, output_size, "SSH client key is not available yet.");
        }
    } else {
        snprintf(output, output_size, "Usage:\n/ssh pubkey  Show the device public key for authorized_keys");
    }
    cJSON_Delete(input);
    return ESP_OK;
}

static esp_err_t cap_ssh_group_start(void)
{
    if (s_ssh.worker) {
        return ESP_OK;
    }
    s_ssh.queue = xQueueCreate(2, sizeof(cap_ssh_job_t *));
    if (!s_ssh.queue) {
        return ESP_ERR_NO_MEM;
    }
    /* libssh key exchange, Ed25519 signing and mbedTLS need a deep stack. */
    if (claw_task_create(&(claw_task_config_t) {
                             .name = "ssh_worker",
                             .stack_size = 16384,
                             .priority = 5,
                             .core_id = tskNO_AFFINITY,
                             .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                         },
                         cap_ssh_worker_task, NULL, &s_ssh.worker) != pdPASS) {
        vQueueDelete(s_ssh.queue);
        s_ssh.queue = NULL;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static const claw_cap_descriptor_t s_ssh_descriptors[] = {
    {
        .id = "ssh_exec",
        .name = "ssh_exec",
        .family = "system",
        .description = s_ssh.description,
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM | CLAW_CAP_FLAG_ROOT_AGENT_ONLY,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"host\":{\"type\":\"string\",\"description\":\"Configured host name\"},"
        "\"command\":{\"type\":\"string\",\"description\":\"Shell command to run\"}},"
        "\"required\":[\"host\",\"command\"]}",
        .execute = cap_ssh_exec_execute,
    },
    {
        .id = "ssh_command",
        .name = "ssh_command",
        .family = "system",
        .description = "Handle the /ssh chat command.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = cap_ssh_command_execute,
    },
};

static const claw_cap_group_t s_ssh_group = {
    .group_id = "cap_ssh",
    .descriptors = s_ssh_descriptors,
    .descriptor_count = sizeof(s_ssh_descriptors) / sizeof(s_ssh_descriptors[0]),
    .group_start = cap_ssh_group_start,
};

esp_err_t cap_ssh_register_group(void)
{
    if (claw_cap_group_exists(s_ssh_group.group_id)) {
        return ESP_OK;
    }

    return claw_cap_register_group(&s_ssh_group);
}

esp_err_t cap_ssh_set_hosts(const char *hosts_json)
{
    cJSON *hosts = NULL;
    cJSON *entry = NULL;
    size_t len;

    if (!hosts_json) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_ssh.hosts_json, hosts_json, sizeof(s_ssh.hosts_json));
    len = (size_t)snprintf(s_ssh.description, sizeof(s_ssh.description),
                           "Run a shell command on a configured SSH host. Every call needs the user's "
                           "confirmation in Telegram. Hosts:");
    hosts = cJSON_Parse(hosts_json);
    cJSON_ArrayForEach(entry, (cJSON_IsArray(hosts) ? hosts : NULL)) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));

        if (name && len < sizeof(s_ssh.description)) {
            len += (size_t)snprintf(s_ssh.description + len, sizeof(s_ssh.description) - len, " %s", name);
        }
    }
    if (!cJSON_GetArraySize(hosts)) {
        if (hosts_json[0]) {
            ESP_LOGW(TAG, "ssh_hosts is not a JSON array of hosts");
        }
        strlcat(s_ssh.description, " none configured", sizeof(s_ssh.description));
    }
    cJSON_Delete(hosts);
    return ESP_OK;
}
