/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "claw_memory_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"

#define CLAW_MEMORY_EMBED_TIMEOUT_MS   15000
#define CLAW_MEMORY_EMBED_BATCH_MAX    64
#define CLAW_MEMORY_EMBED_CACHE_SIZE   4
#define CLAW_MEMORY_EMBED_SRC_DIM_MAX  3072
#define CLAW_MEMORY_VECTOR_ID_MAX      24
#define CLAW_MEMORY_VECTOR_MAGIC       0x31564d43u /* CMV1 */

static const char *TAG = "claw_memory";

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t dim;
    uint16_t slot_size;
} claw_memory_vector_header_t;

/* Fixed-size slot so an update rewrites only its own bytes; id[0] == 0 is free. */
typedef struct __attribute__((packed)) {
    char id[CLAW_MEMORY_VECTOR_ID_MAX];
    float scale;
    int8_t vec[CLAW_MEMORY_EMBED_DIM];
} claw_memory_vector_slot_t;

typedef struct {
    char text[128];
    float vec[CLAW_MEMORY_EMBED_DIM];
    uint32_t used;
} claw_memory_embed_cache_entry_t;

static struct {
    char *base_url;
    char *api_key;
    char *model;
    bool enabled;
    claw_memory_vector_slot_t *slots;
    size_t slot_count;
    bool loaded;
    claw_memory_embed_cache_entry_t *cache;
    uint32_t cache_clock;
    SemaphoreHandle_t cache_lock;
} s_embed;

esp_err_t claw_memory_embed_init(const claw_memory_embed_config_t *config)
{
    free(s_embed.base_url);
    free(s_embed.api_key);
    free(s_embed.model);
    heap_caps_free(s_embed.slots);
    s_embed.base_url = NULL;
    s_embed.api_key = NULL;
    s_embed.model = NULL;
    s_embed.slots = NULL;
    s_embed.slot_count = 0;
    s_embed.loaded = false;
    s_embed.enabled = false;

    if (!s_embed.cache_lock) {
        s_embed.cache_lock = xSemaphoreCreateMutex();
    }
    if (!s_embed.cache) {
        s_embed.cache = heap_caps_calloc(CLAW_MEMORY_EMBED_CACHE_SIZE, sizeof(*s_embed.cache),
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    } else {
        memset(s_embed.cache, 0, CLAW_MEMORY_EMBED_CACHE_SIZE * sizeof(*s_embed.cache));
    }
    if (!s_embed.cache_lock || !s_embed.cache) {
        return ESP_ERR_NO_MEM;
    }
    if (!config || !config->api_key || !config->api_key[0] ||
        !config->base_url || !config->base_url[0] || !config->model || !config->model[0]) {
        ESP_LOGI(TAG, "Semantic recall disabled: no embeddings key");
        return ESP_OK;
    }
    s_embed.base_url = strdup(config->base_url);
    s_embed.api_key = strdup(config->api_key);
    s_embed.model = strdup(config->model);
    if (!s_embed.base_url || !s_embed.api_key || !s_embed.model) {
        return ESP_ERR_NO_MEM;
    }
    s_embed.enabled = true;
    ESP_LOGI(TAG, "Semantic recall enabled model=%s dim=%d", s_embed.model, CLAW_MEMORY_EMBED_DIM);
    return ESP_OK;
}

bool claw_memory_embed_enabled(void)
{
    return s_embed.enabled;
}

static esp_err_t claw_memory_embed_decode(const cJSON *embedding, float *out)
{
    size_t i;

    if (cJSON_IsString(embedding)) {
        /* base64 of little-endian float32, the native layout of the ESP32 */
        size_t src_len = strlen(embedding->valuestring);
        size_t max_bytes = CLAW_MEMORY_EMBED_SRC_DIM_MAX * sizeof(float);
        unsigned char *raw = heap_caps_malloc(max_bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        size_t raw_len = 0;
        int rc;

        if (!raw) {
            return ESP_ERR_NO_MEM;
        }
        rc = mbedtls_base64_decode(raw, max_bytes, &raw_len,
                                   (const unsigned char *)embedding->valuestring, src_len);
        if (rc != 0 || raw_len < CLAW_MEMORY_EMBED_DIM * sizeof(float)) {
            heap_caps_free(raw);
            return ESP_ERR_INVALID_RESPONSE;
        }
        memcpy(out, raw, CLAW_MEMORY_EMBED_DIM * sizeof(float));
        heap_caps_free(raw);
        return ESP_OK;
    }
    if (!cJSON_IsArray(embedding) || cJSON_GetArraySize(embedding) < CLAW_MEMORY_EMBED_DIM) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    for (i = 0; i < CLAW_MEMORY_EMBED_DIM; i++) {
        out[i] = (float)cJSON_GetNumberValue(cJSON_GetArrayItem(embedding, (int)i));
    }
    return ESP_OK;
}

esp_err_t claw_memory_embed_texts(const char *const *texts, size_t count, float *out_vectors)
{
    esp_http_client_config_t config = {0};
    esp_http_client_handle_t client = NULL;
    cJSON *body = NULL;
    cJSON *input = NULL;
    cJSON *root = NULL;
    cJSON *data = NULL;
    cJSON *entry = NULL;
    char *post = NULL;
    char *auth = NULL;
    char *url = NULL;
    char *resp = NULL;
    bool *filled = NULL;
    size_t resp_cap = count * 1600 + 4096;
    size_t resp_len = 0;
    size_t base_len;
    size_t i;
    int status = 0;
    esp_err_t err = ESP_OK;

    if (!s_embed.enabled) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!texts || count == 0 || count > CLAW_MEMORY_EMBED_BATCH_MAX || !out_vectors) {
        return ESP_ERR_INVALID_ARG;
    }

    body = cJSON_CreateObject();
    input = cJSON_AddArrayToObject(body, "input");
    for (i = 0; input && i < count; i++) {
        cJSON_AddItemToArray(input, cJSON_CreateString(texts[i] ? texts[i] : ""));
    }
    cJSON_AddStringToObject(body, "model", s_embed.model);
    cJSON_AddNumberToObject(body, "dimensions", CLAW_MEMORY_EMBED_DIM);
    cJSON_AddStringToObject(body, "encoding_format", "base64");
    post = body && input ? cJSON_PrintUnformatted(body) : NULL;
    cJSON_Delete(body);

    base_len = strlen(s_embed.base_url);
    while (base_len > 0 && s_embed.base_url[base_len - 1] == '/') {
        base_len--;
    }
    url = dup_printf("%.*s/embeddings", (int)base_len, s_embed.base_url);
    auth = dup_printf("Bearer %s", s_embed.api_key);
    resp = heap_caps_malloc(resp_cap + 1, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    filled = calloc(count, sizeof(*filled));
    if (!post || !url || !auth || !resp || !filled) {
        err = ESP_ERR_NO_MEM;
        goto cleanup;
    }

    config.url = url;
    config.method = HTTP_METHOD_POST;
    config.timeout_ms = CLAW_MEMORY_EMBED_TIMEOUT_MS;
    config.buffer_size = 2048;
    config.buffer_size_tx = 2048;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    client = esp_http_client_init(&config);
    if (!client) {
        err = ESP_FAIL;
        goto cleanup;
    }
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Authorization", auth);

    err = esp_http_client_open(client, (int)strlen(post));
    if (err == ESP_OK && esp_http_client_write(client, post, (int)strlen(post)) != (int)strlen(post)) {
        err = ESP_FAIL;
    }
    if (err == ESP_OK && esp_http_client_fetch_headers(client) < 0) {
        err = ESP_FAIL;
    }
    if (err == ESP_OK) {
        status = esp_http_client_get_status_code(client);
        while (resp_len < resp_cap) {
            int n = esp_http_client_read(client, resp + resp_len, (int)(resp_cap - resp_len));

            if (n < 0) {
                err = ESP_FAIL;
                break;
            }
            if (n == 0) {
                break;
            }
            resp_len += (size_t)n;
        }
    }
    resp[resp_len] = '\0';
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "embeddings request failed: %s", esp_err_to_name(err));
        goto cleanup;
    }
    if (status < 200 || status >= 300) {
        ESP_LOGW(TAG, "embeddings HTTP %d: %.160s", status, resp);
        err = ESP_FAIL;
        goto cleanup;
    }

    root = cJSON_Parse(resp);
    data = cJSON_GetObjectItem(root, "data");
    if (!cJSON_IsArray(data)) {
        data = NULL;
    }
    cJSON_ArrayForEach(entry, data) {
        int index = (int)cJSON_GetNumberValue(cJSON_GetObjectItem(entry, "index"));

        if (index < 0 || (size_t)index >= count ||
            claw_memory_embed_decode(cJSON_GetObjectItem(entry, "embedding"),
                                     out_vectors + (size_t)index * CLAW_MEMORY_EMBED_DIM) != ESP_OK) {
            continue;
        }
        filled[index] = true;
    }
    for (i = 0; i < count; i++) {
        if (!filled[i]) {
            ESP_LOGW(TAG, "embeddings response incomplete (%u inputs)", (unsigned)count);
            err = ESP_ERR_INVALID_RESPONSE;
            break;
        }
    }

cleanup:
    if (client) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
    }
    cJSON_Delete(root);
    cJSON_free(post);
    free(url);
    free(auth);
    free(filled);
    heap_caps_free(resp);
    return err;
}

esp_err_t claw_memory_embed_query(const char *text, float *out_vector)
{
    claw_memory_embed_cache_entry_t *slot = NULL;
    size_t i;
    esp_err_t err;

    if (!text || !text[0] || !out_vector) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_embed.cache_lock, portMAX_DELAY);
    for (i = 0; i < CLAW_MEMORY_EMBED_CACHE_SIZE; i++) {
        if (s_embed.cache[i].used && strncmp(s_embed.cache[i].text, text, sizeof(s_embed.cache[i].text)) == 0 &&
            strlen(text) < sizeof(s_embed.cache[i].text)) {
            memcpy(out_vector, s_embed.cache[i].vec, sizeof(s_embed.cache[i].vec));
            s_embed.cache[i].used = ++s_embed.cache_clock;
            xSemaphoreGive(s_embed.cache_lock);
            return ESP_OK;
        }
    }
    xSemaphoreGive(s_embed.cache_lock);

    err = claw_memory_embed_texts(&text, 1, out_vector);
    if (err != ESP_OK || strlen(text) >= sizeof(s_embed.cache[0].text)) {
        return err;
    }

    xSemaphoreTake(s_embed.cache_lock, portMAX_DELAY);
    for (i = 0; i < CLAW_MEMORY_EMBED_CACHE_SIZE; i++) {
        if (!slot || s_embed.cache[i].used < slot->used) {
            slot = &s_embed.cache[i];
        }
    }
    safe_copy(slot->text, sizeof(slot->text), text);
    memcpy(slot->vec, out_vector, sizeof(slot->vec));
    slot->used = ++s_embed.cache_clock;
    xSemaphoreGive(s_embed.cache_lock);
    return ESP_OK;
}

static void claw_memory_vectors_load(void)
{
    claw_memory_vector_header_t header = {0};
    FILE *file;
    size_t size;
    size_t count;

    if (s_embed.loaded) {
        return;
    }
    s_embed.loaded = true;
    size = file_size_bytes(s_memory.vectors_path);
    file = size > sizeof(header) ? fopen(s_memory.vectors_path, "rb") : NULL;
    if (!file) {
        return;
    }
    if (fread(&header, 1, sizeof(header), file) != sizeof(header) ||
        header.magic != CLAW_MEMORY_VECTOR_MAGIC || header.dim != CLAW_MEMORY_EMBED_DIM ||
        header.slot_size != sizeof(claw_memory_vector_slot_t)) {
        ESP_LOGW(TAG, "Ignoring incompatible %s", CLAW_MEMORY_VECTORS_FILE);
        fclose(file);
        return;
    }
    count = (size - sizeof(header)) / sizeof(claw_memory_vector_slot_t);
    s_embed.slots = heap_caps_calloc(count ? count : 1, sizeof(*s_embed.slots),
                                     MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (s_embed.slots) {
        s_embed.slot_count = fread(s_embed.slots, sizeof(*s_embed.slots), count, file);
    }
    fclose(file);
}

static esp_err_t claw_memory_vectors_write_slot(size_t index)
{
    claw_memory_vector_header_t header = {
        .magic = CLAW_MEMORY_VECTOR_MAGIC,
        .dim = CLAW_MEMORY_EMBED_DIM,
        .slot_size = sizeof(claw_memory_vector_slot_t),
    };
    FILE *file = fopen(s_memory.vectors_path, "r+b");
    esp_err_t err = ESP_OK;

    if (!file) {
        file = fopen(s_memory.vectors_path, "w+b");
        if (!file || fwrite(&header, 1, sizeof(header), file) != sizeof(header)) {
            if (file) {
                fclose(file);
            }
            return ESP_FAIL;
        }
    }
    if (fseek(file, (long)(sizeof(header) + index * sizeof(claw_memory_vector_slot_t)), SEEK_SET) != 0 ||
        fwrite(&s_embed.slots[index], 1, sizeof(s_embed.slots[index]), file) != sizeof(s_embed.slots[index])) {
        err = ESP_FAIL;
    }
    if (fclose(file) != 0) {
        err = ESP_FAIL;
    }
    return err;
}

static int claw_memory_vectors_find(const char *memory_id)
{
    size_t i;

    for (i = 0; memory_id && memory_id[0] && i < s_embed.slot_count; i++) {
        if (strncmp(s_embed.slots[i].id, memory_id, CLAW_MEMORY_VECTOR_ID_MAX) == 0) {
            return (int)i;
        }
    }
    return -1;
}

const int8_t *claw_memory_vectors_get(const char *memory_id)
{
    int index;

    claw_memory_vectors_load();
    index = claw_memory_vectors_find(memory_id);
    return index >= 0 ? s_embed.slots[index].vec : NULL;
}

esp_err_t claw_memory_vectors_put(const char *memory_id, const float *vector)
{
    float scale;
    int index;

    if (!memory_id || strlen(memory_id) >= CLAW_MEMORY_VECTOR_ID_MAX || !vector) {
        return ESP_ERR_INVALID_ARG;
    }
    claw_memory_vectors_load();
    index = claw_memory_vectors_find(memory_id);
    if (index < 0) {
        for (size_t i = 0; i < s_embed.slot_count; i++) {
            if (!s_embed.slots[i].id[0]) {
                index = (int)i;
                break;
            }
        }
    }
    if (index < 0) {
        claw_memory_vector_slot_t *grown = heap_caps_realloc(s_embed.slots,
                                                             (s_embed.slot_count + 1) * sizeof(*grown),
                                                             MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!grown) {
            return ESP_ERR_NO_MEM;
        }
        s_embed.slots = grown;
        index = (int)s_embed.slot_count++;
    }
    memset(&s_embed.slots[index], 0, sizeof(s_embed.slots[index]));
    memcpy(s_embed.slots[index].id, memory_id, strlen(memory_id));
    claw_memory_vec_quantize(vector, s_embed.slots[index].vec, &scale);
    s_embed.slots[index].scale = scale;
    return claw_memory_vectors_write_slot((size_t)index);
}

void claw_memory_vectors_remove(const char *memory_id)
{
    int index;

    claw_memory_vectors_load();
    index = claw_memory_vectors_find(memory_id);
    if (index >= 0) {
        memset(&s_embed.slots[index], 0, sizeof(s_embed.slots[index]));
        (void)claw_memory_vectors_write_slot((size_t)index);
    }
}

size_t claw_memory_vectors_prune(const claw_memory_item_list_t *active)
{
    size_t removed = 0;
    size_t i;

    claw_memory_vectors_load();
    for (i = 0; active && i < s_embed.slot_count; i++) {
        int idx;

        if (!s_embed.slots[i].id[0]) {
            continue;
        }
        idx = claw_memory_find_item_index(active, s_embed.slots[i].id);
        if (idx < 0 || active->items[idx].deleted) {
            memset(&s_embed.slots[i], 0, sizeof(s_embed.slots[i]));
            (void)claw_memory_vectors_write_slot(i);
            removed++;
        }
    }
    return removed;
}
