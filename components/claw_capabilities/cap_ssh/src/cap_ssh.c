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
#include "cap_ssh_rules.h"
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
#define CAP_SSH_COMMAND_MAX        CAP_SSH_RULES_TEXT_MAX
#define CAP_SSH_OUTPUT_MAX         (8 * 1024)
#define CAP_SSH_PROMPT_MAX         4096
#define CAP_SSH_STATUS_RESERVE     192
#define CAP_SSH_CONFIRM_TIMEOUT_MS 60000
#define CAP_SSH_CONNECT_TIMEOUT_S  10
#define CAP_SSH_TOTAL_TIMEOUT_MS   30000
#define CAP_SSH_READ_SLICE_MS      200
#define CAP_SSH_NVS_NAMESPACE      "ssh_client"
#define CAP_SSH_NVS_KEY            "privkey"
#define CAP_SSH_KEY_COMMENT        "esp-claw"
#define CAP_SSH_RULES_MAX          32
#define CAP_SSH_RULE_KEY_FMT       "rule%02d"
#define CAP_SSH_RULE_HOST_MAX      64
#define CAP_SSH_RULE_PATTERN_MAX   (2 * CAP_SSH_COMMAND_MAX + 1)
#define CAP_SSH_RULE_ENTRY_MAX     (CAP_SSH_RULE_HOST_MAX + CAP_SSH_COMMAND_MAX + CAP_SSH_RULE_PATTERN_MAX + 3)
#define CAP_SSH_LABEL_MAX          64
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

    /* ssh_options_apply() expands "%d" in default paths via getpwuid_r(), which fails on
     * ESP-IDF; libssh then falls back to $HOME. No files are read from it. */
    setenv("HOME", "/ssh", 0);
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

typedef bool (*cap_ssh_rule_fn_t)(int slot, const char *host, const char *prog, const char *pattern, void *arg);

/* Calls `fn` for each allow rule in slot order until it returns false. Rules are stored in NVS
 * keys rule00..rule31 as "<host>\n<program>\n<args pattern>"; listed numbers skip empty slots. */
static void cap_ssh_rules_each(cap_ssh_rule_fn_t fn, void *arg)
{
    char *entry = malloc(CAP_SSH_RULE_ENTRY_MAX);
    nvs_handle_t nvs;
    char key[8];

    if (!entry || nvs_open(CAP_SSH_NVS_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK) {
        free(entry);
        return;
    }
    for (int i = 0; i < CAP_SSH_RULES_MAX; i++) {
        size_t len = CAP_SSH_RULE_ENTRY_MAX;
        char *prog = NULL;
        char *pattern = NULL;

        snprintf(key, sizeof(key), CAP_SSH_RULE_KEY_FMT, i);
        if (nvs_get_str(nvs, key, entry, &len) != ESP_OK || !(prog = strchr(entry, '\n')) ||
                !(pattern = strchr(prog + 1, '\n'))) {
            continue;
        }
        *prog++ = '\0';
        *pattern++ = '\0';
        if (!fn(i, entry, prog, pattern, arg)) {
            break;
        }
    }
    nvs_close(nvs);
    free(entry);
}

/* Stores `value` in rule slot `slot`, or erases the slot when `value` is NULL. */
static esp_err_t cap_ssh_rule_write(int slot, const char *value)
{
    nvs_handle_t nvs;
    char key[8];
    esp_err_t err = nvs_open(CAP_SSH_NVS_NAMESPACE, NVS_READWRITE, &nvs);

    if (err != ESP_OK) {
        return err;
    }
    snprintf(key, sizeof(key), CAP_SSH_RULE_KEY_FMT, slot);
    err = value ? nvs_set_str(nvs, key, value) : nvs_erase_key(nvs, key);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return err;
}

typedef struct {
    const char *host;
    const char *prog;
    const char *pattern;
    uint32_t used;
    bool exists;
} cap_ssh_rule_add_t;

static bool cap_ssh_rule_add_cb(int slot, const char *host, const char *prog, const char *pattern, void *arg)
{
    cap_ssh_rule_add_t *add = arg;

    add->used |= 1u << slot;
    add->exists |= strcmp(host, add->host) == 0 && strcmp(prog, add->prog) == 0 &&
                   strcmp(pattern, add->pattern) == 0;
    return true;
}

/* ESP_ERR_INVALID_SIZE means all slots are used; an identical rule counts as added. */
static esp_err_t cap_ssh_rule_add(const char *host, const char *prog, const char *pattern)
{
    cap_ssh_rule_add_t add = {.host = host, .prog = prog, .pattern = pattern};
    char *value = NULL;
    int slot = 0;
    esp_err_t err;

    if (strlen(host) > CAP_SSH_RULE_HOST_MAX || strchr(host, '\n')) {
        return ESP_ERR_INVALID_ARG;
    }
    cap_ssh_rules_each(cap_ssh_rule_add_cb, &add);
    if (add.exists) {
        return ESP_OK;
    }
    while (slot < CAP_SSH_RULES_MAX && (add.used & (1u << slot))) {
        slot++;
    }
    if (slot == CAP_SSH_RULES_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    value = malloc(CAP_SSH_RULE_ENTRY_MAX);
    if (!value) {
        return ESP_ERR_NO_MEM;
    }
    snprintf(value, CAP_SSH_RULE_ENTRY_MAX, "%s\n%s\n%s", host, prog, pattern);
    err = cap_ssh_rule_write(slot, value);
    free(value);
    return err;
}

typedef struct {
    int number;
    int seen;
    uint32_t slots;
} cap_ssh_rule_pick_t;

static bool cap_ssh_rule_pick_cb(int slot, const char *host, const char *prog, const char *pattern, void *arg)
{
    cap_ssh_rule_pick_t *pick = arg;

    (void)host;
    (void)prog;
    (void)pattern;
    if (!pick->number || ++pick->seen == pick->number) {
        pick->slots |= 1u << slot;
    }
    return true;
}

/* Removes the `number`-th rule (1-based, as listed), or every rule when `number` is 0. */
static esp_err_t cap_ssh_rule_revoke(int number)
{
    cap_ssh_rule_pick_t pick = {.number = number};
    esp_err_t err = number ? ESP_ERR_NOT_FOUND : ESP_OK;

    cap_ssh_rules_each(cap_ssh_rule_pick_cb, &pick);
    for (int i = 0; i < CAP_SSH_RULES_MAX; i++) {
        if (pick.slots & (1u << i)) {
            err = cap_ssh_rule_write(i, NULL);
            if (err != ESP_OK) {
                break;
            }
        }
    }
    return err;
}

typedef struct {
    const char *host;
    char *out;
    size_t size;
    size_t len;
    int seen;
} cap_ssh_rule_print_t;

/* Appends "n. host: `rule`" lines, or only ", rule" items of `host` when it is set. */
static bool cap_ssh_rule_print_cb(int slot, const char *host, const char *prog, const char *pattern, void *arg)
{
    cap_ssh_rule_print_t *print = arg;

    (void)slot;
    if (print->host && strcmp(host, print->host) != 0) {
        return true;
    }
    print->seen++;
    if (print->host) {
        print->len += (size_t)snprintf(print->out + print->len, print->size - print->len, "%s%s%s%s",
                                       print->seen > 1 ? ", " : "", prog, pattern[0] ? " " : "", pattern);
    } else {
        print->len += (size_t)snprintf(print->out + print->len, print->size - print->len, "%d. %s: `%s%s%s`\n",
                                       print->seen, host, prog, pattern[0] ? " " : "", pattern);
    }
    return print->len < print->size;
}

/* Lists every host and the rules that run on it without confirmation, so the LLM prefers those
 * forms. The capability registry reads the buffer on every request, so changes apply live. */
static void cap_ssh_build_description(void)
{
    char *desc = calloc(1, CAP_SSH_DESCRIPTION_MAX);
    cJSON *hosts = cJSON_Parse(s_ssh.hosts_json);
    cJSON *entry = NULL;
    cap_ssh_rule_print_t print = {.out = desc, .size = CAP_SSH_DESCRIPTION_MAX};

    if (!desc) {
        cJSON_Delete(hosts);
        return;
    }
    print.len = (size_t)snprintf(desc, print.size, "Run a shell command on a configured SSH host. Asks the user "
                                 "in Telegram unless the host's allow rules cover it. Hosts:");
    cJSON_ArrayForEach(entry, (cJSON_IsArray(hosts) ? hosts : NULL)) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));
        size_t before;

        if (!name || print.len >= print.size) {
            continue;
        }
        print.len += (size_t)snprintf(desc + print.len, print.size - print.len, " %s (no prompt: ", name);
        before = print.len;
        print.host = name;
        print.seen = 0;
        cap_ssh_rules_each(cap_ssh_rule_print_cb, &print);
        if (print.len < print.size) {
            print.len += (size_t)snprintf(desc + print.len, print.size - print.len, ")");
        }
        if (print.len == before + 1) {
            print.len -= strlen(" (no prompt: )");
            desc[print.len] = '\0';
        }
    }
    if (!cJSON_GetArraySize(hosts)) {
        if (s_ssh.hosts_json[0]) {
            ESP_LOGW(TAG, "ssh_hosts is not a JSON array of hosts");
        }
        strlcat(desc, " none configured", CAP_SSH_DESCRIPTION_MAX);
    }
    strlcpy(s_ssh.description, desc, sizeof(s_ssh.description));
    cJSON_Delete(hosts);
    free(desc);
}

typedef struct {
    const char *host;
    const cap_ssh_rules_parsed_t *parsed;
    bool allowed[CAP_SSH_RULES_CMDS_MAX];
} cap_ssh_rule_check_t;

static bool cap_ssh_rule_check_cb(int slot, const char *host, const char *prog, const char *pattern, void *arg)
{
    cap_ssh_rule_check_t *check = arg;

    (void)slot;
    for (size_t i = 0; strcmp(host, check->host) == 0 && i < check->parsed->count; i++) {
        check->allowed[i] |= strcmp(prog, check->parsed->cmds[i].prog) == 0 &&
                             cap_ssh_rules_match(pattern, check->parsed->cmds[i].args);
    }
    return true;
}

/* Adds an exact ("Genau so") or widest ("Immer") rule for every simple command no rule covers. */
static esp_err_t cap_ssh_add_rules(const cap_ssh_rule_check_t *check, bool wildcard)
{
    char *pattern = malloc(CAP_SSH_RULE_PATTERN_MAX);
    esp_err_t err = pattern ? ESP_OK : ESP_ERR_NO_MEM;

    for (size_t i = 0; err == ESP_OK && i < check->parsed->count; i++) {
        const cap_ssh_rules_cmd_t *cmd = &check->parsed->cmds[i];

        if (check->allowed[i]) {
            continue;
        }
        if (wildcard) {
            cap_ssh_rules_wildcard(cmd, pattern, CAP_SSH_RULE_PATTERN_MAX);
        } else if (!cap_ssh_rules_escape(cmd->args, pattern, CAP_SSH_RULE_PATTERN_MAX)) {
            err = ESP_ERR_INVALID_SIZE;
            break;
        }
        err = cap_ssh_rule_add(check->host, cmd->prog, pattern);
    }
    free(pattern);
    cap_ssh_build_description();
    return err;
}

/* Builds "🔁 Immer: df *, free *" from the widest rules, cut short with "…". */
static void cap_ssh_wildcard_label(const cap_ssh_rule_check_t *check, char *label)
{
    char item[CAP_SSH_LABEL_MAX];
    char pattern[32];
    size_t len = strlcpy(label, "🔁 Immer:", CAP_SSH_LABEL_MAX);

    for (size_t i = 0; i < check->parsed->count; i++) {
        if (check->allowed[i]) {
            continue;
        }
        cap_ssh_rules_wildcard(&check->parsed->cmds[i], pattern, sizeof(pattern));
        snprintf(item, sizeof(item), " %s %s,", check->parsed->cmds[i].prog, pattern);
        if (strstr(label, item)) {
            continue;
        }
        if (len + strlen(item) + strlen("…") >= CAP_SSH_LABEL_MAX) {
            strlcat(label, " …,", CAP_SSH_LABEL_MAX);
            break;
        }
        len = strlcat(label, item, CAP_SSH_LABEL_MAX);
    }
    label[strlen(label) - 1] = '\0';
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
                                  const char *status, const char *note)
{
    snprintf(html + prompt_len, CAP_SSH_PROMPT_MAX - prompt_len, "\n\n<b>%s</b>%s", status, note);
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
    cap_ssh_rules_parsed_t *parsed = NULL;
    cap_ssh_rule_check_t check = {0};
    char *html = NULL;
    size_t prompt_len = 0;
    char port[8];
    char status[48];
    char wildcard_label[CAP_SSH_LABEL_MAX];
    const char *labels[] = {"✅ Einmal", "🔁 Genau so", wildcard_label, "❌ Abbrechen"};
    const char *const short_labels[] = {"✅ Einmal", "❌ Abbrechen"};
    const char *note = "";
    bool offer_rules = false;
    bool auto_allowed = false;
    int64_t message_id = 0;
    int choice = -1;
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
    parsed = heap_caps_malloc(sizeof(*parsed), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!job || !html || !parsed) {
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

    /* Every simple command must be covered by a rule and none may be hardline; commands that are
     * not auto-approvable or contain a hardline program get no rule buttons. */
    check.host = name;
    check.parsed = parsed;
    offer_rules = cap_ssh_rules_parse(command, parsed);
    for (size_t i = 0; offer_rules && i < parsed->count; i++) {
        offer_rules = !cap_ssh_rules_hardline(parsed->cmds[i].prog, parsed->cmds[i].args);
    }
    if (offer_rules) {
        cap_ssh_rules_each(cap_ssh_rule_check_cb, &check);
        auto_allowed = true;
        for (size_t i = 0; i < parsed->count; i++) {
            auto_allowed &= check.allowed[i];
        }
        cap_ssh_wildcard_label(&check, wildcard_label);
    }

    snprintf(port, sizeof(port), "%u", job->port);
    {
        /* Odd entries are config or LLM data and get escaped. */
        const char *confirm_parts[] = {
            "<b>SSH-Befehl bestätigen</b>\nHost: <b>", name, "</b> (", job->user, "@", job->host,
            ":", port, ")\n<pre>", command, "</pre>",
        };
        const char *auto_parts[] = {"🔁 automatisch erlaubt: <b>", name, "</b>:\n<pre>", command, "</pre>"};
        const char **parts = auto_allowed ? auto_parts : confirm_parts;
        size_t count = auto_allowed ? sizeof(auto_parts) / sizeof(auto_parts[0]) :
                       sizeof(confirm_parts) / sizeof(confirm_parts[0]);

        for (size_t i = 0; i < count; i++) {
            if (!cap_ssh_html_put(html, &prompt_len, parts[i], i % 2 == 1)) {
                err = ESP_ERR_INVALID_SIZE;
                snprintf(output, output_size, "Error: command too long to show for confirmation");
                goto cleanup;
            }
        }
    }

    if (auto_allowed) {
        choice = 0;
        err = cap_im_tg_send_html(ctx->chat_id, html, &message_id);
    } else {
        err = cap_im_tg_confirm(ctx->chat_id, html, offer_rules ? labels : short_labels,
                                offer_rules ? 4 : 2, CAP_SSH_CONFIRM_TIMEOUT_MS, &choice, &message_id);
    }
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: could not %s in Telegram (%s)",
                 auto_allowed ? "send the notice" : "ask for confirmation", esp_err_to_name(err));
        goto cleanup;
    }
    if (offer_rules && (choice == 1 || choice == 2)) {
        esp_err_t save_err = cap_ssh_add_rules(&check, choice == 2);

        note = save_err == ESP_OK ? "\n🔁 Regel gespeichert" :
               save_err == ESP_ERR_INVALID_SIZE ? "\n⚠️ Regel nicht gespeichert: Liste voll (max. 32, /ssh revoke)" :
               "\n⚠️ Regel nicht gespeichert";
        if (save_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to store ssh allow rule: %s", esp_err_to_name(save_err));
        }
    } else if (choice != 0) {
        bool timeout = choice < 0;

        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len,
                              timeout ? "⌛ Zeitüberschreitung" : "❌ abgelehnt", note);
        snprintf(output, output_size, "Error: %s",
                 timeout ? "Zeitüberschreitung: keine Bestätigung innerhalb von 60 s" : "abgelehnt vom Benutzer");
        err = timeout ? ESP_ERR_TIMEOUT : ESP_FAIL;
        goto cleanup;
    }

    job->out = heap_caps_calloc(1, CAP_SSH_OUTPUT_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    job->err = heap_caps_calloc(1, CAP_SSH_OUTPUT_MAX + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    job->done = xSemaphoreCreateBinary();
    if (!job->out || !job->err || !job->done || xQueueSend(s_ssh.queue, &job, 0) != pdTRUE) {
        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, "⚠️ fehlgeschlagen", note);
        err = ESP_ERR_NO_MEM;
        snprintf(output, output_size, "Error: could not start the SSH session");
        goto cleanup;
    }
    /* The worker bounds every step with its own timeouts. */
    xSemaphoreTake(job->done, portMAX_DELAY);

    if (job->error[0]) {
        cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, "⚠️ fehlgeschlagen", note);
        snprintf(output, output_size, "Error: ssh %s: %s", name, job->error);
        err = ESP_FAIL;
        goto cleanup;
    }
    if (job->timed_out) {
        strlcpy(status, "⌛ abgebrochen nach 30 s", sizeof(status));
    } else {
        snprintf(status, sizeof(status), "✅ ausgeführt (exit %d)", job->exit_code);
    }
    cap_ssh_finish_prompt(ctx->chat_id, message_id, html, prompt_len, status, note);
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
    free(parsed);
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
    char name[CAP_SSH_RULE_HOST_MAX + 1];
    int number = 0;
    int offset = 0;
    esp_err_t err;

    (void)ctx;
    if (command && strcmp(command, "pubkey") == 0) {
        if (s_ssh.key_ready) {
            snprintf(output, output_size, "`%s`", s_ssh.pubkey);
        } else {
            snprintf(output, output_size, "SSH client key is not available yet.");
        }
    } else if (command && strcmp(command, "allowed") == 0) {
        cap_ssh_rule_print_t print = {.out = output, .size = output_size};

        output[0] = '\0';
        cap_ssh_rules_each(cap_ssh_rule_print_cb, &print);
        if (!print.seen) {
            snprintf(output, output_size, "No SSH allow rules.");
        }
    } else if (command && (strcmp(command, "revoke all") == 0 ||
                           (sscanf(command, "revoke %d", &number) == 1 && number > 0))) {
        err = cap_ssh_rule_revoke(number);
        cap_ssh_build_description();
        snprintf(output, output_size, err == ESP_OK ? "Revoked." : err == ESP_ERR_NOT_FOUND ?
                 "No such rule, see /ssh allowed." : "Error: %s", esp_err_to_name(err));
    } else if (command && sscanf(command, "allow %64s %n", name, &offset) == 1 && offset > 0) {
        cap_ssh_rules_parsed_t *parsed = malloc(sizeof(*parsed));
        cap_ssh_job_t *job = calloc(1, sizeof(*job));

        /* "<program> [args pattern]" is canonicalized like a command; unquoted * ? [ stay globs. */
        if (!parsed || !job) {
            snprintf(output, output_size, "Error: out of memory");
        } else if (!cap_ssh_rules_parse(command + offset, parsed) || parsed->count != 1) {
            snprintf(output, output_size, "Error: give one program and an optional args pattern without "
                     "operators, redirections or substitutions.");
        } else if (cap_ssh_rules_hardline(parsed->cmds[0].prog, parsed->cmds[0].args)) {
            snprintf(output, output_size, "Error: %s is on the hardline list and always needs confirmation.",
                     parsed->cmds[0].prog);
        } else if (cap_ssh_lookup_host(name, job, output, output_size)) {
            err = cap_ssh_rule_add(name, parsed->cmds[0].prog, parsed->cmds[0].args);
            cap_ssh_build_description();
            if (err == ESP_OK) {
                snprintf(output, output_size, "Allowed on %s: `%s %s`", name, parsed->cmds[0].prog,
                         parsed->cmds[0].args);
            } else {
                snprintf(output, output_size, err == ESP_ERR_INVALID_SIZE ?
                         "Error: all 32 rules are used, see /ssh revoke." : "Error: %s", esp_err_to_name(err));
            }
        }
        free(parsed);
        free(job);
    } else {
        snprintf(output, output_size,
                 "Usage:\n/ssh pubkey  Show the device public key for authorized_keys\n"
                 "/ssh allowed  List rules that run without confirmation\n"
                 "/ssh allow <host> <program> [args|*]  Add a rule (* and ? are globs)\n"
                 "/ssh revoke <n>|all  Remove rules");
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
    if (!hosts_json) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_ssh.hosts_json, hosts_json, sizeof(s_ssh.hosts_json));
    cap_ssh_build_description();
    return ESP_OK;
}
