/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_wol.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "claw_cap.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"

static const char *TAG = "cap_wol";

#define CAP_WOL_TARGETS_MAX     1024
#define CAP_WOL_DESCRIPTION_MAX 320
#define CAP_WOL_PACKET_LEN      102
#define CAP_WOL_SEND_COUNT      3
#define CAP_WOL_SEND_GAP_MS     100

typedef struct {
    char targets_json[CAP_WOL_TARGETS_MAX];
    char description[CAP_WOL_DESCRIPTION_MAX];
} cap_wol_state_t;

static EXT_RAM_BSS_ATTR cap_wol_state_t s_wol;

/* Accepts AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF with one separator throughout. */
static bool cap_wol_parse_mac(const char *text, uint8_t mac[6])
{
    if (!text || strlen(text) != 17) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        unsigned int byte = 0;

        for (int j = 0; j < 2; j++) {
            char c = text[i * 3 + j];
            int nibble = c >= '0' && c <= '9' ? c - '0' :
                         c >= 'a' && c <= 'f' ? c - 'a' + 10 :
                         c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;

            if (nibble < 0) {
                return false;
            }
            byte = (byte << 4) | (unsigned int)nibble;
        }
        if (i < 5 && (text[i * 3 + 2] != text[2] || (text[2] != ':' && text[2] != '-'))) {
            return false;
        }
        mac[i] = (uint8_t)byte;
    }
    return true;
}

/* Directed broadcast of the STA interface, or the limited broadcast without an address. */
static uint32_t cap_wol_default_broadcast(void)
{
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info = { 0 };

    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK && ip_info.ip.addr != 0) {
        return ip_info.ip.addr | ~ip_info.netmask.addr;
    }
    return htonl(INADDR_BROADCAST);
}

static esp_err_t cap_wol_send(const uint8_t mac[6], uint32_t addr, uint16_t port, char *error, size_t error_size)
{
    uint8_t packet[CAP_WOL_PACKET_LEN];
    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = addr,
    };
    int enable = 1;
    int sock;
    esp_err_t err = ESP_OK;

    memset(packet, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(packet + 6 + i * 6, mac, 6);
    }

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        snprintf(error, error_size, "socket failed (errno %d)", errno);
        return ESP_FAIL;
    }
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) != 0) {
        snprintf(error, error_size, "SO_BROADCAST failed (errno %d)", errno);
        err = ESP_FAIL;
    }
    for (int i = 0; err == ESP_OK && i < CAP_WOL_SEND_COUNT; i++) {
        if (i > 0) {
            vTaskDelay(pdMS_TO_TICKS(CAP_WOL_SEND_GAP_MS));
        }
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) != sizeof(packet)) {
            snprintf(error, error_size, "sendto failed (errno %d)", errno);
            err = ESP_FAIL;
        }
    }
    close(sock);
    return err;
}

static esp_err_t cap_wol_wake_execute(const char *input_json,
                                      const claw_cap_call_context_t *ctx,
                                      char *output,
                                      size_t output_size)
{
    cJSON *input = cJSON_Parse(input_json);
    cJSON *targets = cJSON_Parse(s_wol.targets_json);
    cJSON *entry = NULL;
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(input, "target"));
    const char *mac_text = NULL;
    const char *broadcast_text = NULL;
    cJSON *port_item = NULL;
    uint8_t mac[6];
    struct in_addr addr;
    char addr_text[INET_ADDRSTRLEN];
    char mac_norm[18];
    char error[64];
    cJSON *result = NULL;
    char *rendered = NULL;
    int port = 9;
    esp_err_t err = ESP_ERR_INVALID_ARG;

    (void)ctx;
    if (!name || !name[0]) {
        snprintf(output, output_size, "Error: target is required");
        goto cleanup;
    }
    cJSON_ArrayForEach(entry, (cJSON_IsArray(targets) ? targets : NULL)) {
        const char *entry_name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));

        if (entry_name && strcmp(entry_name, name) == 0) {
            break;
        }
    }
    if (!entry) {
        snprintf(output, output_size, "Error: unknown wol target '%s'", name);
        goto cleanup;
    }

    mac_text = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "mac"));
    broadcast_text = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "broadcast"));
    port_item = cJSON_GetObjectItem(entry, "port");
    if (!cap_wol_parse_mac(mac_text, mac)) {
        snprintf(output, output_size, "Error: wol target '%s' has an invalid mac", name);
        goto cleanup;
    }
    if (port_item) {
        port = cJSON_IsNumber(port_item) ? port_item->valueint : 0;
        if (port <= 0 || port > 65535) {
            snprintf(output, output_size, "Error: wol target '%s' has an invalid port", name);
            goto cleanup;
        }
    }
    if (broadcast_text && broadcast_text[0]) {
        if (inet_pton(AF_INET, broadcast_text, &addr) != 1) {
            snprintf(output, output_size, "Error: wol target '%s' has an invalid broadcast address", name);
            goto cleanup;
        }
    } else {
        addr.s_addr = cap_wol_default_broadcast();
    }
    inet_ntop(AF_INET, &addr, addr_text, sizeof(addr_text));

    err = cap_wol_send(mac, addr.s_addr, (uint16_t)port, error, sizeof(error));
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: wol %s: %s", name, error);
        goto cleanup;
    }
    ESP_LOGI(TAG, "Magic packet for %s sent to %s:%d", name, addr_text, port);
    snprintf(mac_norm, sizeof(mac_norm), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    result = cJSON_CreateObject();
    if (result) {
        cJSON_AddStringToObject(result, "target", name);
        cJSON_AddStringToObject(result, "mac", mac_norm);
        cJSON_AddStringToObject(result, "broadcast", addr_text);
        cJSON_AddNumberToObject(result, "port", port);
        cJSON_AddBoolToObject(result, "sent", true);
        rendered = cJSON_PrintUnformatted(result);
        cJSON_Delete(result);
    }
    snprintf(output, output_size, "%s", rendered ? rendered : "{\"sent\":true}");
    free(rendered);

cleanup:
    cJSON_Delete(targets);
    cJSON_Delete(input);
    return err;
}

static const claw_cap_descriptor_t s_wol_descriptors[] = {
    {
        .id = "wol_wake",
        .name = "wol_wake",
        .family = "system",
        .description = s_wol.description,
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json =
        "{\"type\":\"object\",\"properties\":{\"target\":{\"type\":\"string\",\"description\":\"Configured target name\"}},"
        "\"required\":[\"target\"]}",
        .execute = cap_wol_wake_execute,
    },
};

static const claw_cap_group_t s_wol_group = {
    .group_id = "cap_wol",
    .descriptors = s_wol_descriptors,
    .descriptor_count = sizeof(s_wol_descriptors) / sizeof(s_wol_descriptors[0]),
};

esp_err_t cap_wol_register_group(void)
{
    if (claw_cap_group_exists(s_wol_group.group_id)) {
        return ESP_OK;
    }

    return claw_cap_register_group(&s_wol_group);
}

esp_err_t cap_wol_set_targets(const char *targets_json)
{
    cJSON *targets = NULL;
    cJSON *entry = NULL;
    size_t len;

    if (!targets_json) {
        return ESP_ERR_INVALID_ARG;
    }

    strlcpy(s_wol.targets_json, targets_json, sizeof(s_wol.targets_json));
    len = (size_t)snprintf(s_wol.description, sizeof(s_wol.description),
                           "Wake a configured machine with a Wake-on-LAN magic packet. Targets:");
    targets = cJSON_Parse(targets_json);
    cJSON_ArrayForEach(entry, (cJSON_IsArray(targets) ? targets : NULL)) {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItem(entry, "name"));

        if (name && len < sizeof(s_wol.description)) {
            len += (size_t)snprintf(s_wol.description + len, sizeof(s_wol.description) - len, " %s", name);
        }
    }
    if (!cJSON_GetArraySize(targets)) {
        if (targets_json[0]) {
            ESP_LOGW(TAG, "wol_targets is not a JSON array of targets");
        }
        strlcat(s_wol.description, " none configured", sizeof(s_wol.description));
    }
    cJSON_Delete(targets);
    return ESP_OK;
}
