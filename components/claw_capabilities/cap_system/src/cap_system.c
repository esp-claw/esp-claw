/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "cap_system.h"
#include "cap_system_storage.h"

#include <dirent.h>
#include <stdbool.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>

#include "cJSON.h"
#include "claw_cap.h"
#include "claw_version.h"
#include "claw_task.h"
#include "claw_paths.h"
#if CONFIG_APP_CLAW_CAP_CORE
#include "claw_agent_mgr.h"
#endif
#if CONFIG_APP_CLAW_CAP_SKILL_MGR
#include "claw_skill.h"
#endif
#if CONFIG_APP_CLAW_CAP_LUA
#include "cap_lua.h"
#endif
#include "driver/temperature_sensor.h"
#include "esp_check.h"
#include "esp_app_desc.h"
#include "esp_chip_info.h"
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
#include "esp_core_dump.h"
#endif
#include "esp_err.h"
#include "esp_event.h"
#include "esp_idf_version.h"
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_sntp.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_vfs_fat.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/idf_additions.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "nvs.h"

static const char *TAG = "cap_system";

#define CAP_SYSTEM_RESTART_DEFAULT_DELAY_MS 500
#define CAP_SYSTEM_MIN_VALID_EPOCH          1704067200
#define CAP_SYSTEM_SNTP_PRIMARY_SERVER      "pool.ntp.org"
#define CAP_SYSTEM_SNTP_SECONDARY_SERVER    "time.windows.com"
#define CAP_SYSTEM_SNTP_WAIT_MS             3000
#define CAP_SYSTEM_SNTP_RETRY_COUNT         15
#define CAP_SYSTEM_DEFAULT_DISCONNECTED_RETRY_MS 5000
#define CAP_SYSTEM_DEFAULT_SYNC_RETRY_MS        30000
#define CAP_SYSTEM_CPU_SAMPLE_MS            500
#define CAP_SYSTEM_TASKS_MAX                25
#define CAP_SYSTEM_STATS_NVS_NAMESPACE      "sys_stats"
#define CAP_SYSTEM_BOOT_COUNT_KEY           "boot_count"
#define CAP_SYSTEM_INBOX_MAX_DEPTH          3
#define CAP_SYSTEM_INBOX_MAX_ENTRIES        512
#define CAP_SYSTEM_SUBAGENTS_MAX            16

#ifdef CONFIG_CLAW_CAP_SYSTEM_DEBUG_LOGS
#define CAP_SYSTEM_DEBUG_LOG(label, text) ESP_LOGI(TAG, "%s: %s", label, text)
#else
#define CAP_SYSTEM_DEBUG_LOG(label, text) do { (void)(label); (void)(text); } while (0)
#endif

typedef struct {
    uint32_t delay_ms;
} cap_system_restart_task_args_t;

static SemaphoreHandle_t s_time_mutex = NULL;
static struct {
    TaskHandle_t task_handle;
    cap_system_time_sync_service_config_t config;
    bool running;
} s_time_service = {0};

typedef struct {
    TaskStatus_t *before;
    TaskStatus_t *after;
    UBaseType_t before_count;
    UBaseType_t after_count;
    configRUN_TIME_COUNTER_TYPE total_before;
    configRUN_TIME_COUNTER_TYPE total_after;
} cap_system_cpu_sample_t;

static uint32_t s_boot_count;
static volatile uint32_t s_wifi_disconnect_count;
static esp_event_handler_instance_t s_wifi_disconnect_handler;
static temperature_sensor_handle_t s_temp_sensor;

static esp_err_t cap_system_get_current_time(char *output, size_t output_size);
static esp_err_t cap_system_sync_time_now(char *output, size_t output_size);
static bool cap_system_is_time_valid(void);

static esp_err_t cap_system_ensure_time_mutex(void)
{
    if (!s_time_mutex) {
        s_time_mutex = xSemaphoreCreateMutex();
    }
    return s_time_mutex ? ESP_OK : ESP_ERR_NO_MEM;
}

static void cap_system_time_sync_notification_cb(struct timeval *tv)
{
    (void)tv;
    ESP_LOGI(TAG, "SNTP time synchronization event received");
}

static esp_err_t cap_system_format_current_time(char *output, size_t output_size)
{
    time_t now = 0;
    struct tm local_tm = {0};

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "format current time: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    time(&now);
    if (now < CAP_SYSTEM_MIN_VALID_EPOCH) {
        ESP_LOGW(TAG, "format current time: clock is invalid");
        return ESP_ERR_INVALID_STATE;
    }
    if (!localtime_r(&now, &local_tm)) {
        ESP_LOGE(TAG, "format current time: localtime_r failed");
        return ESP_FAIL;
    }
    if (strftime(output, output_size, "%Y-%m-%d %H:%M:%S %Z (%A)", &local_tm) == 0) {
        ESP_LOGE(TAG, "format current time: buffer too small");
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

static esp_err_t cap_system_sync_with_sntp(char *output, size_t output_size)
{
    esp_err_t err = ESP_OK;
    esp_err_t wait_err = ESP_OK;
    int retry = 0;
#if CONFIG_LWIP_SNTP_MAX_SERVERS > 1
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG_MULTIPLE(
        2,
        ESP_SNTP_SERVER_LIST(CAP_SYSTEM_SNTP_PRIMARY_SERVER, CAP_SYSTEM_SNTP_SECONDARY_SERVER)
    );
#else
    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(CAP_SYSTEM_SNTP_PRIMARY_SERVER);
#endif

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "sync with sntp: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    config.sync_cb = cap_system_time_sync_notification_cb;
    err = esp_netif_sntp_init(&config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sync with sntp init failed: %s", esp_err_to_name(err));
        return err;
    }

    while ((wait_err = esp_netif_sntp_sync_wait(pdMS_TO_TICKS(CAP_SYSTEM_SNTP_WAIT_MS))) == ESP_ERR_TIMEOUT &&
           ++retry < CAP_SYSTEM_SNTP_RETRY_COUNT) {
        ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, CAP_SYSTEM_SNTP_RETRY_COUNT);
    }

    if (wait_err != ESP_OK) {
        err = wait_err;
        ESP_LOGE(TAG, "sync with sntp wait failed: %s", esp_err_to_name(err));
        goto done;
    }

    err = cap_system_format_current_time(output, output_size);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sync with sntp format failed: %s", esp_err_to_name(err));
    }

done:
    esp_netif_sntp_deinit();
    return err;
}

static bool cap_system_time_network_ready(void)
{
    if (!s_time_service.config.network_ready) {
        return true;
    }

    return s_time_service.config.network_ready(s_time_service.config.network_ready_ctx);
}

static void cap_system_notify_time_sync_success(bool had_valid_time)
{
    if (s_time_service.config.on_sync_success) {
        s_time_service.config.on_sync_success(had_valid_time, s_time_service.config.on_sync_success_ctx);
    }
}

static void cap_system_time_sync_service_task(void *arg)
{
    char output[256];

    (void)arg;

    while (s_time_service.running) {
        bool time_valid;
        uint32_t delay_ms;

        if (!cap_system_time_network_ready()) {
            delay_ms = s_time_service.config.disconnected_retry_ms;
            vTaskDelay(pdMS_TO_TICKS(delay_ms));
            continue;
        }

        time_valid = cap_system_is_time_valid();
        if (!time_valid) {
            esp_err_t err;

            output[0] = '\0';
            err = cap_system_sync_time_now(output, sizeof(output));
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "Time sync succeeded: %s", output);
                cap_system_notify_time_sync_success(false);
                break;
            }

            ESP_LOGW(TAG, "Time sync failed: %s", esp_err_to_name(err));
            delay_ms = s_time_service.config.sync_retry_ms;
            vTaskDelay(pdMS_TO_TICKS(delay_ms));
            continue;
        }

        cap_system_notify_time_sync_success(false);
        break;
    }

    s_time_service.running = false;
    s_time_service.task_handle = NULL;
    claw_task_delete(NULL);
}

static const char *cap_system_wifi_auth_mode_to_str(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN:
            return "open";
        case WIFI_AUTH_WEP:
            return "wep";
        case WIFI_AUTH_WPA_PSK:
            return "wpa_psk";
        case WIFI_AUTH_WPA2_PSK:
            return "wpa2_psk";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "wpa_wpa2_psk";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "wpa2_enterprise";
        case WIFI_AUTH_WPA3_PSK:
            return "wpa3_psk";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "wpa2_wpa3_psk";
        case WIFI_AUTH_WAPI_PSK:
            return "wapi_psk";
        default:
            return "unknown";
    }
}

static esp_err_t cap_system_render_json(cJSON *root, char *output, size_t output_size)
{
    char *rendered = NULL;

    if (!root || !output || output_size == 0) {
        ESP_LOGE(TAG, "render json: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    rendered = cJSON_PrintUnformatted(root);
    if (!rendered) {
        ESP_LOGE(TAG, "render json: no mem");
        return ESP_ERR_NO_MEM;
    }

    snprintf(output, output_size, "%s", rendered);
    free(rendered);
    return ESP_OK;
}

static cJSON *cap_system_build_memory_json(void)
{
    cJSON *root = cJSON_CreateObject();
    size_t psram_total = 0;

    if (!root) {
        ESP_LOGE(TAG, "memory json: create failed");
        return NULL;
    }

    cJSON_AddNumberToObject(root, "internal_free", (double)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "internal_total", (double)heap_caps_get_total_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "internal_min_free", (double)heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "internal_largest_free_block", (double)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    cJSON_AddNumberToObject(root, "dma_free", (double)heap_caps_get_free_size(MALLOC_CAP_DMA));
    cJSON_AddNumberToObject(root, "dma_min_free", (double)heap_caps_get_minimum_free_size(MALLOC_CAP_DMA));
    cJSON_AddNumberToObject(root, "dma_largest_free_block", (double)heap_caps_get_largest_free_block(MALLOC_CAP_DMA));
    cJSON_AddNumberToObject(root, "heap_free", (double)esp_get_free_heap_size());
    cJSON_AddNumberToObject(root, "heap_min_free", (double)esp_get_minimum_free_heap_size());

    psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    cJSON_AddBoolToObject(root, "psram_available", psram_total > 0);
    if (psram_total > 0) {
        cJSON_AddNumberToObject(root, "psram_free", (double)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(root, "psram_total", (double)psram_total);
        cJSON_AddNumberToObject(root, "psram_min_free", (double)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM));
        cJSON_AddNumberToObject(root,
                                "psram_largest_free_block",
                                (double)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
    }

    return root;
}

static esp_err_t cap_system_get_sta_ip_info(esp_netif_ip_info_t *ip_info)
{
    esp_netif_t *netif = NULL;

    if (!ip_info) {
        ESP_LOGE(TAG, "sta ip: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) {
        ESP_LOGE(TAG, "sta ip: netif not found");
        return ESP_ERR_NOT_FOUND;
    }

    return esp_netif_get_ip_info(netif, ip_info);
}

static cJSON *cap_system_build_ip_json(void)
{
    cJSON *root = cJSON_CreateObject();
    esp_netif_ip_info_t ip_info = {0};
    esp_err_t err;
    char ip_buf[16];
    char netmask_buf[16];
    char gateway_buf[16];

    if (!root) {
        ESP_LOGE(TAG, "ip json: create failed");
        return NULL;
    }

    err = cap_system_get_sta_ip_info(&ip_info);
    if (err != ESP_OK || ip_info.ip.addr == 0) {
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "ip info unavailable: %s", esp_err_to_name(err));
        }
        cJSON_AddBoolToObject(root, "connected", false);
        cJSON_AddNullToObject(root, "ip");
        cJSON_AddNullToObject(root, "netmask");
        cJSON_AddNullToObject(root, "gateway");
        return root;
    }

    snprintf(ip_buf, sizeof(ip_buf), IPSTR, IP2STR(&ip_info.ip));
    snprintf(netmask_buf, sizeof(netmask_buf), IPSTR, IP2STR(&ip_info.netmask));
    snprintf(gateway_buf, sizeof(gateway_buf), IPSTR, IP2STR(&ip_info.gw));

    cJSON_AddBoolToObject(root, "connected", true);
    cJSON_AddStringToObject(root, "ip", ip_buf);
    cJSON_AddStringToObject(root, "netmask", netmask_buf);
    cJSON_AddStringToObject(root, "gateway", gateway_buf);
    return root;
}

static cJSON *cap_system_build_wifi_json(void)
{
    cJSON *root = cJSON_CreateObject();
    wifi_ap_record_t ap_info = {0};
    uint8_t primary = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    wifi_mode_t mode = WIFI_MODE_NULL;
    wifi_sta_list_t sta_list = {0};
    esp_err_t err;
    char bssid_buf[18];
    char phy_buf[24];

    if (!root) {
        ESP_LOGE(TAG, "wifi json: create failed");
        return NULL;
    }

    cJSON_AddNumberToObject(root, "disconnect_count", s_wifi_disconnect_count);
    if (esp_wifi_get_mode(&mode) == ESP_OK && (mode & WIFI_MODE_AP)) {
        cJSON_AddBoolToObject(root, "ap_active", true);
        cJSON_AddNumberToObject(root, "ap_stations", esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK ? sta_list.num : 0);
    } else {
        cJSON_AddBoolToObject(root, "ap_active", false);
    }

    err = esp_wifi_sta_get_ap_info(&ap_info);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "wifi ap info failed: %s", esp_err_to_name(err));
        cJSON_AddBoolToObject(root, "connected", false);
        cJSON_AddStringToObject(root, "status", "disconnected");
        return root;
    }

    snprintf(bssid_buf,
             sizeof(bssid_buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             ap_info.bssid[0],
             ap_info.bssid[1],
             ap_info.bssid[2],
             ap_info.bssid[3],
             ap_info.bssid[4],
             ap_info.bssid[5]);

    cJSON_AddBoolToObject(root, "connected", true);
    cJSON_AddStringToObject(root, "status", "connected");
    cJSON_AddStringToObject(root, "ssid", (const char *)ap_info.ssid);
    cJSON_AddStringToObject(root, "bssid", bssid_buf);
    cJSON_AddNumberToObject(root, "rssi", ap_info.rssi);
    cJSON_AddNumberToObject(root, "channel", ap_info.primary);
    cJSON_AddStringToObject(root, "auth_mode", cap_system_wifi_auth_mode_to_str(ap_info.authmode));
    snprintf(phy_buf,
             sizeof(phy_buf),
             "11%s%s%s%s%s",
             ap_info.phy_11b ? "b" : "",
             ap_info.phy_11g ? "g" : "",
             ap_info.phy_11n ? "n" : "",
             ap_info.phy_11ax ? "ax" : "",
             ap_info.phy_lr ? "+lr" : "");
    cJSON_AddStringToObject(root, "phy_mode", phy_buf);

    if (esp_wifi_get_channel(&primary, &second) == ESP_OK) {
        cJSON_AddNumberToObject(root, "primary_channel", primary);
        cJSON_AddNumberToObject(root, "second_channel", second);
    } else {
        ESP_LOGW(TAG, "wifi channel failed");
    }

    return root;
}

static void cap_system_cpu_sample_free(cap_system_cpu_sample_t *sample)
{
    free(sample->before);
    free(sample->after);
    memset(sample, 0, sizeof(*sample));
}

// Two task snapshots CAP_SYSTEM_CPU_SAMPLE_MS apart; blocks the calling task for that window.
static esp_err_t cap_system_cpu_sample_take(cap_system_cpu_sample_t *sample)
{
    memset(sample, 0, sizeof(*sample));
#if CONFIG_FREERTOS_GENERATE_RUN_TIME_STATS && CONFIG_FREERTOS_USE_TRACE_FACILITY
    UBaseType_t capacity = uxTaskGetNumberOfTasks() + 4;

    sample->before = calloc(capacity, sizeof(TaskStatus_t));
    if (!sample->before) {
        ESP_LOGE(TAG, "cpu sample: no mem");
        return ESP_ERR_NO_MEM;
    }
    sample->before_count = uxTaskGetSystemState(sample->before, capacity, &sample->total_before);
    vTaskDelay(pdMS_TO_TICKS(CAP_SYSTEM_CPU_SAMPLE_MS));

    capacity = uxTaskGetNumberOfTasks() + 4;
    sample->after = calloc(capacity, sizeof(TaskStatus_t));
    if (!sample->after) {
        ESP_LOGE(TAG, "cpu sample: no mem");
        cap_system_cpu_sample_free(sample);
        return ESP_ERR_NO_MEM;
    }
    sample->after_count = uxTaskGetSystemState(sample->after, capacity, &sample->total_after);
    return ESP_OK;
#else
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

// Run time a task accumulated inside the sample window (whole counter if it was created during it).
static configRUN_TIME_COUNTER_TYPE cap_system_task_window_runtime(const cap_system_cpu_sample_t *sample,
                                                                  const TaskStatus_t *task)
{
    for (UBaseType_t i = 0; i < sample->before_count; i++) {
        if (sample->before[i].xHandle == task->xHandle) {
            return task->ulRunTimeCounter - sample->before[i].ulRunTimeCounter;
        }
    }
    return task->ulRunTimeCounter;
}

static double cap_system_percent(double part, double whole)
{
    double percent = whole > 0 ? (part * 100.0) / whole : 0;

    percent = percent < 0 ? 0 : (percent > 100.0 ? 100.0 : percent);
    return round(percent * 10.0) / 10.0;
}

static cJSON *cap_system_build_cpu_json(const cap_system_cpu_sample_t *sample)
{
    cJSON *root = cJSON_CreateObject();

    if (!root) {
        ESP_LOGE(TAG, "cpu json: create failed");
        return NULL;
    }

    if (sample && sample->after) {
        // On SMP the run time counter is wall-clock time, so each IDLE task is measured against one core.
        configRUN_TIME_COUNTER_TYPE window = sample->total_after - sample->total_before;
        cJSON *per_core = cJSON_AddArrayToObject(root, "per_core_percent");
        double usage_sum = 0;
        double idle_since_boot = 0;

        for (int core = 0; core < portNUM_PROCESSORS; core++) {
            TaskHandle_t idle = xTaskGetIdleTaskHandleForCore(core);
            double usage = 0;

            for (UBaseType_t i = 0; i < sample->after_count; i++) {
                if (sample->after[i].xHandle == idle) {
                    usage = 100.0 - cap_system_percent(cap_system_task_window_runtime(sample, &sample->after[i]), window);
                    idle_since_boot += sample->after[i].ulRunTimeCounter;
                    break;
                }
            }
            usage_sum += usage;
            cJSON_AddItemToArray(per_core, cJSON_CreateNumber(usage));
        }

        cJSON_AddBoolToObject(root, "supported", true);
        cJSON_AddNumberToObject(root, "usage_percent", round(usage_sum * 10.0 / portNUM_PROCESSORS) / 10.0);
        cJSON_AddNumberToObject(root, "window_ms", CAP_SYSTEM_CPU_SAMPLE_MS);
        // A 32-bit microsecond counter wraps after ~71 min, after which a since-boot average is meaningless.
        if (sizeof(configRUN_TIME_COUNTER_TYPE) >= sizeof(uint64_t) || esp_timer_get_time() < (int64_t)UINT32_MAX) {
            cJSON_AddNumberToObject(root,
                                    "since_boot_percent",
                                    100.0 - cap_system_percent(idle_since_boot,
                                                               (double)sample->total_after * portNUM_PROCESSORS));
        } else {
            cJSON_AddNullToObject(root, "since_boot_percent");
        }
        cJSON_AddNumberToObject(root, "task_count", sample->after_count);
    } else {
        cJSON_AddBoolToObject(root, "supported", false);
        cJSON_AddStringToObject(root, "message", "FreeRTOS run time stats are disabled or sampling failed");
    }

    cJSON_AddNumberToObject(root, "core_count", portNUM_PROCESSORS);
    cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000));
    return root;
}

typedef struct {
    const TaskStatus_t *task;
    configRUN_TIME_COUNTER_TYPE runtime;
} cap_system_task_usage_t;

static int cap_system_task_usage_cmp(const void *a, const void *b)
{
    const cap_system_task_usage_t *lhs = a;
    const cap_system_task_usage_t *rhs = b;

    return (lhs->runtime < rhs->runtime) - (lhs->runtime > rhs->runtime);
}

static const char *cap_system_task_state_to_str(eTaskState state)
{
    switch (state) {
        case eRunning:
            return "running";
        case eReady:
            return "ready";
        case eBlocked:
            return "blocked";
        case eSuspended:
            return "suspended";
        case eDeleted:
            return "deleted";
        default:
            return "invalid";
    }
}

static cJSON *cap_system_build_tasks_json(const cap_system_cpu_sample_t *sample)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *list = NULL;
    cap_system_task_usage_t *usage = NULL;
    configRUN_TIME_COUNTER_TYPE window;

    if (!root) {
        ESP_LOGE(TAG, "tasks json: create failed");
        return NULL;
    }
    if (!sample || !sample->after) {
        cJSON_AddBoolToObject(root, "supported", false);
        cJSON_AddStringToObject(root, "message", "FreeRTOS run time stats are disabled or sampling failed");
        return root;
    }

    usage = calloc(sample->after_count, sizeof(*usage));
    if (!usage) {
        ESP_LOGE(TAG, "tasks json: no mem");
        cJSON_Delete(root);
        return NULL;
    }
    for (UBaseType_t i = 0; i < sample->after_count; i++) {
        usage[i].task = &sample->after[i];
        usage[i].runtime = cap_system_task_window_runtime(sample, &sample->after[i]);
    }
    qsort(usage, sample->after_count, sizeof(*usage), cap_system_task_usage_cmp);

    window = sample->total_after - sample->total_before;
    cJSON_AddBoolToObject(root, "supported", true);
    cJSON_AddNumberToObject(root, "window_ms", CAP_SYSTEM_CPU_SAMPLE_MS);
    cJSON_AddNumberToObject(root, "task_count", sample->after_count);
    list = cJSON_AddArrayToObject(root, "tasks");
    for (UBaseType_t i = 0; i < sample->after_count && i < CAP_SYSTEM_TASKS_MAX; i++) {
        const TaskStatus_t *task = usage[i].task;
        BaseType_t core = xTaskGetCoreID(task->xHandle);
        cJSON *item = cJSON_CreateObject();

        if (!item) {
            break;
        }
        cJSON_AddStringToObject(item, "name", task->pcTaskName);
        cJSON_AddStringToObject(item, "state", cap_system_task_state_to_str(task->eCurrentState));
        cJSON_AddNumberToObject(item, "priority", task->uxCurrentPriority);
        if (core == tskNO_AFFINITY) {
            cJSON_AddStringToObject(item, "core", "any");
        } else {
            cJSON_AddNumberToObject(item, "core", core);
        }
        cJSON_AddNumberToObject(item, "cpu_percent", cap_system_percent(usage[i].runtime, window));
        // StackType_t is uint8_t on ESP-IDF, so the high-water mark is already in bytes.
        cJSON_AddNumberToObject(item, "stack_min_free_bytes", task->usStackHighWaterMark * sizeof(StackType_t));
        cJSON_AddItemToArray(list, item);
    }

    free(usage);
    return root;
}

static const char *cap_system_reset_reason_to_str(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:
            return "power_on";
        case ESP_RST_EXT:
            return "external_pin";
        case ESP_RST_SW:
            return "software";
        case ESP_RST_PANIC:
            return "panic";
        case ESP_RST_INT_WDT:
            return "interrupt_watchdog";
        case ESP_RST_TASK_WDT:
            return "task_watchdog";
        case ESP_RST_WDT:
            return "other_watchdog";
        case ESP_RST_DEEPSLEEP:
            return "deep_sleep";
        case ESP_RST_BROWNOUT:
            return "brownout";
        case ESP_RST_SDIO:
            return "sdio";
        case ESP_RST_USB:
            return "usb";
        case ESP_RST_JTAG:
            return "jtag";
        case ESP_RST_EFUSE:
            return "efuse";
        case ESP_RST_PWR_GLITCH:
            return "power_glitch";
        case ESP_RST_CPU_LOCKUP:
            return "cpu_lockup";
        default:
            return "unknown";
    }
}

static cJSON *cap_system_build_reset_json(void)
{
    cJSON *root = cJSON_CreateObject();

    if (!root) {
        ESP_LOGE(TAG, "reset json: create failed");
        return NULL;
    }

    cJSON_AddStringToObject(root, "reason", cap_system_reset_reason_to_str(esp_reset_reason()));
    cJSON_AddNumberToObject(root, "boot_count", s_boot_count);
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
    cJSON *coredump = cJSON_AddObjectToObject(root, "coredump");
    bool present = esp_core_dump_image_check() == ESP_OK;

    cJSON_AddBoolToObject(coredump, "present", present);
#if CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF
    esp_core_dump_summary_t *summary = present ? calloc(1, sizeof(*summary)) : NULL;
    char pc_buf[11];

    if (summary && esp_core_dump_get_summary(summary) == ESP_OK) {
        snprintf(pc_buf, sizeof(pc_buf), "0x%08" PRIx32, summary->exc_pc);
        cJSON_AddStringToObject(coredump, "task", summary->exc_task);
        cJSON_AddStringToObject(coredump, "pc", pc_buf);
#if CONFIG_IDF_TARGET_ARCH_XTENSA
        cJSON_AddNumberToObject(coredump, "exc_cause", summary->ex_info.exc_cause);
#endif
    }
    free(summary);
#endif
#else
    cJSON_AddStringToObject(root, "coredump", "disabled");
#endif
    return root;
}

// Sums regular files below path (len chars used); stops descending past depth and after *budget entries.
static void cap_system_scan_dir(char *path, size_t len, size_t path_size, int depth,
                                uint64_t *bytes, uint32_t *files, uint32_t *budget)
{
    DIR *dir = opendir(path);
    struct dirent *entry = NULL;

    if (!dir) {
        return;
    }
    while (*budget > 0 && (entry = readdir(dir)) != NULL) {
        struct stat st = {0};
        int written = snprintf(path + len, path_size - len, "/%s", entry->d_name);

        (*budget)--;
        if (written <= 0 || len + (size_t)written >= path_size || stat(path, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (depth > 0) {
                cap_system_scan_dir(path, len + (size_t)written, path_size, depth - 1, bytes, files, budget);
            }
        } else if (S_ISREG(st.st_mode)) {
            *bytes += (uint64_t)st.st_size;
            (*files)++;
        }
    }
    path[len] = '\0';
    closedir(dir);
}

static cJSON *cap_system_build_storage_json(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *nvs = NULL;
    cJSON *app = NULL;
    const char *data_path = claw_paths_get(CLAW_PATH_DATA);
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    esp_image_metadata_t image = {0};
    nvs_stats_t nvs_stats = {0};
    uint64_t total = 0;
    uint64_t free_bytes = 0;
    uint64_t inbox_bytes = 0;
    uint32_t inbox_files = 0;
    uint32_t budget = CAP_SYSTEM_INBOX_MAX_ENTRIES;
    char path[256];

    if (!root) {
        ESP_LOGE(TAG, "storage json: create failed");
        return NULL;
    }

    if (data_path && data_path[0] && esp_vfs_fat_info(data_path, &total, &free_bytes) == ESP_OK) {
        cJSON_AddStringToObject(root, "data_path", data_path);
        cJSON_AddNumberToObject(root, "fs_total", (double)total);
        cJSON_AddNumberToObject(root, "fs_free", (double)free_bytes);
    } else {
        cJSON_AddNullToObject(root, "data_path");
    }

    if (claw_paths_join(CLAW_PATH_DATA, "inbox", path, sizeof(path)) == ESP_OK) {
        cap_system_scan_dir(path, strlen(path), sizeof(path), CAP_SYSTEM_INBOX_MAX_DEPTH,
                            &inbox_bytes, &inbox_files, &budget);
        cJSON_AddNumberToObject(root, "inbox_bytes", (double)inbox_bytes);
        cJSON_AddNumberToObject(root, "inbox_files", inbox_files);
        cJSON_AddBoolToObject(root, "inbox_truncated", budget == 0);
    }

    if (nvs_get_stats(NULL, &nvs_stats) == ESP_OK) {
        nvs = cJSON_AddObjectToObject(root, "nvs");
        cJSON_AddNumberToObject(nvs, "used_entries", nvs_stats.used_entries);
        cJSON_AddNumberToObject(nvs, "free_entries", nvs_stats.free_entries);
        cJSON_AddNumberToObject(nvs, "total_entries", nvs_stats.total_entries);
        cJSON_AddNumberToObject(nvs, "namespaces", nvs_stats.namespace_count);
    }

    if (running) {
        app = cJSON_AddObjectToObject(root, "app");
        cJSON_AddStringToObject(app, "partition", running->label);
        cJSON_AddNumberToObject(app, "partition_size", running->size);
        if (esp_image_get_metadata(&(esp_partition_pos_t) {
                .offset = running->address,
                .size = running->size,
            }, &image) == ESP_OK) {
            cJSON_AddNumberToObject(app, "image_size", image.image_len);
        }
        /* Without an ota_1 slot IDF hands back the running partition itself. */
        cJSON_AddBoolToObject(app, "ota_slot_available", next != NULL && next != running);
        if (next && next != running) {
            cJSON_AddStringToObject(app, "next_partition", next->label);
        }
    }

    return root;
}

static cJSON *cap_system_build_temperature_json(void)
{
    cJSON *root = cJSON_CreateObject();
    float celsius = 0;
    esp_err_t err = ESP_OK;

    if (!root) {
        ESP_LOGE(TAG, "temperature json: create failed");
        return NULL;
    }

    // Installed lazily on first use and left enabled; the sensor is only read here.
    if (!s_temp_sensor) {
        temperature_sensor_config_t config = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
        temperature_sensor_handle_t handle = NULL;

        err = temperature_sensor_install(&config, &handle);
        if (err == ESP_OK) {
            err = temperature_sensor_enable(handle);
            if (err == ESP_OK) {
                s_temp_sensor = handle;
            } else {
                temperature_sensor_uninstall(handle);
            }
        }
    }
    if (err == ESP_OK) {
        err = temperature_sensor_get_celsius(s_temp_sensor, &celsius);
    }

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "temperature read failed: %s", esp_err_to_name(err));
        cJSON_AddNullToObject(root, "chip_celsius");
        cJSON_AddStringToObject(root, "error", esp_err_to_name(err));
        return root;
    }

    cJSON_AddNumberToObject(root, "chip_celsius", round(celsius * 10.0) / 10.0);
    return root;
}

static cJSON *cap_system_build_network_json(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *dns = NULL;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info = {0};
    int open_sockets = 0;
    char buf[16];

    if (!root) {
        ESP_LOGE(TAG, "network json: create failed");
        return NULL;
    }

    // An lwIP descriptor is open when fcntl() on it succeeds; there are only LWIP_MAX_SOCKETS of them.
    for (int i = 0; i < CONFIG_LWIP_MAX_SOCKETS; i++) {
        if (lwip_fcntl(LWIP_SOCKET_OFFSET + i, F_GETFL, 0) >= 0) {
            open_sockets++;
        }
    }
    cJSON_AddNumberToObject(root, "sockets_open", open_sockets);
    cJSON_AddNumberToObject(root, "sockets_max", CONFIG_LWIP_MAX_SOCKETS);

    if (!netif || esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        cJSON_AddBoolToObject(root, "sta_connected", false);
        return root;
    }

    cJSON_AddBoolToObject(root, "sta_connected", true);
    snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip_info.netmask));
    cJSON_AddStringToObject(root, "netmask", buf);
    snprintf(buf, sizeof(buf), IPSTR, IP2STR(&ip_info.gw));
    cJSON_AddStringToObject(root, "gateway", buf);
    dns = cJSON_AddArrayToObject(root, "dns");
    for (esp_netif_dns_type_t type = ESP_NETIF_DNS_MAIN; type <= ESP_NETIF_DNS_BACKUP; type++) {
        esp_netif_dns_info_t dns_info = {0};

        if (esp_netif_get_dns_info(netif, type, &dns_info) == ESP_OK &&
                dns_info.ip.type == ESP_IPADDR_TYPE_V4 && dns_info.ip.u_addr.ip4.addr != 0) {
            snprintf(buf, sizeof(buf), IPSTR, IP2STR(&dns_info.ip.u_addr.ip4));
            cJSON_AddItemToArray(dns, cJSON_CreateString(buf));
        }
    }
    return root;
}

#if CONFIG_APP_CLAW_CAP_SKILL_MGR
static esp_err_t cap_system_count_skill(const claw_skill_catalog_entry_t *entry, void *user_ctx)
{
    (void)entry;
    (*(size_t *)user_ctx)++;
    return ESP_OK;
}
#endif

static cJSON *cap_system_build_claw_json(const claw_cap_call_context_t *ctx)
{
    cJSON *root = cJSON_CreateObject();

    if (!root) {
        ESP_LOGE(TAG, "claw json: create failed");
        return NULL;
    }

    cJSON_AddNumberToObject(root, "capabilities", claw_cap_list().count);
    cJSON_AddNumberToObject(root, "cap_groups", claw_cap_list_groups().count);
#if CONFIG_APP_CLAW_CAP_SKILL_MGR
    size_t skills = 0;

    if (claw_skill_foreach_catalog_entry(cap_system_count_skill, &skills) == ESP_OK) {
        cJSON_AddNumberToObject(root, "skills", skills);
    } else {
        cJSON_AddNullToObject(root, "skills");
    }
#endif
#if CONFIG_APP_CLAW_CAP_LUA
    cJSON_AddNumberToObject(root, "lua_async_jobs", cap_lua_get_active_async_job_count());
#endif
#if CONFIG_APP_CLAW_CAP_CORE
    // The agent manager only lists the sub-agents of the calling session.
    claw_agent_mgr_agent_info_t *infos = calloc(CAP_SYSTEM_SUBAGENTS_MAX, sizeof(*infos));
    size_t count = 0;

    if (infos && claw_agent_mgr_list_agents(ctx, infos, CAP_SYSTEM_SUBAGENTS_MAX, &count) == ESP_OK) {
        cJSON *subagents = cJSON_AddObjectToObject(root, "session_subagents");
        size_t running = 0;

        for (size_t i = 0; i < count; i++) {
            running += infos[i].status == CLAW_AGENT_MGR_STATUS_RUNNING;
        }
        cJSON_AddNumberToObject(subagents, "total", count);
        cJSON_AddNumberToObject(subagents, "running", running);
    } else {
        cJSON_AddNullToObject(root, "session_subagents");
    }
    free(infos);
#else
    (void)ctx;
#endif
    return root;
}

static cJSON *cap_system_build_version_json(void)
{
    cJSON *root = cJSON_CreateObject();

    if (!root) {
        ESP_LOGE(TAG, "version json: create failed");
        return NULL;
    }

    // ESP-Claw comes from claw_core; Edge Agent comes from ESP-IDF PROJECT_VER embedded in esp_app_desc.
    cJSON_AddStringToObject(root, "esp_claw", claw_get_version());
    cJSON_AddStringToObject(root, "esp_claw_git", claw_get_git_version());
    cJSON_AddStringToObject(root, "edge_agent", esp_app_get_description()->version);
    cJSON_AddStringToObject(root, "esp_idf", esp_get_idf_version());
    return root;
}

static cJSON *cap_system_build_info_json(void)
{
    cJSON *root = cJSON_CreateObject();
    esp_chip_info_t chip_info = {0};
    cap_system_cpu_sample_t sample;

    if (!root) {
        ESP_LOGE(TAG, "system json: create failed");
        return NULL;
    }

    esp_chip_info(&chip_info);
    cJSON_AddStringToObject(root, "chip_model", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(root, "chip_revision", chip_info.revision);
    cJSON_AddNumberToObject(root, "core_count", chip_info.cores);
    cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000));
    cJSON_AddItemToObject(root, "version", cap_system_build_version_json());
    cJSON_AddItemToObject(root, "memory", cap_system_build_memory_json());
    cap_system_cpu_sample_take(&sample);
    cJSON_AddItemToObject(root, "cpu", cap_system_build_cpu_json(&sample));
    cap_system_cpu_sample_free(&sample);
    cJSON_AddItemToObject(root, "wifi", cap_system_build_wifi_json());
    cJSON_AddItemToObject(root, "ip", cap_system_build_ip_json());
    cJSON_AddItemToObject(root, "reset", cap_system_build_reset_json());
    cJSON_AddItemToObject(root, "storage", cap_system_build_storage_json());
    return root;
}

static bool cap_system_section_is_requested(const cJSON *sections, const char *section)
{
    const cJSON *item = NULL;

    if (!sections || !section) {
        return false;
    }

    cJSON_ArrayForEach(item, sections) {
        if (cJSON_IsString(item) && item->valuestring && strcmp(item->valuestring, section) == 0) {
            return true;
        }
    }

    return false;
}

static esp_err_t cap_system_add_section(cJSON *root, const char *name, cJSON *section)
{
    if (!section) {
        ESP_LOGE(TAG, "add json section failed: %s", name);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddItemToObject(root, name, section);
    return ESP_OK;
}

static esp_err_t cap_system_add_json_section(cJSON *root, const char *name, cJSON *(*builder)(void))
{
    if (!root || !name || !builder) {
        ESP_LOGE(TAG, "add json section: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    return cap_system_add_section(root, name, builder());
}

static esp_err_t cap_system_add_chip_section(cJSON *root)
{
    cJSON *chip = NULL;
    esp_chip_info_t chip_info = {0};

    if (!root) {
        ESP_LOGE(TAG, "add chip section: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    chip = cJSON_CreateObject();
    if (!chip) {
        ESP_LOGE(TAG, "chip section: create failed");
        return ESP_ERR_NO_MEM;
    }

    esp_chip_info(&chip_info);
    cJSON_AddStringToObject(chip, "chip_model", CONFIG_IDF_TARGET);
    cJSON_AddNumberToObject(chip, "chip_revision", chip_info.revision);
    cJSON_AddNumberToObject(chip, "core_count", chip_info.cores);
    cJSON_AddItemToObject(root, "chip", chip);
    return ESP_OK;
}

static esp_err_t cap_system_add_uptime_section(cJSON *root)
{
    if (!root) {
        ESP_LOGE(TAG, "add uptime section: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    cJSON_AddNumberToObject(root, "uptime_ms", (double)(esp_timer_get_time() / 1000));
    return ESP_OK;
}

static esp_err_t cap_system_build_selected_info_json(const cJSON *sections,
                                                     const claw_cap_call_context_t *ctx,
                                                     char *output,
                                                     size_t output_size)
{
    cJSON *root = NULL;
    cap_system_cpu_sample_t sample = {0};
    esp_err_t ret = ESP_OK;

    if (!sections || !cJSON_IsArray(sections) || cJSON_GetArraySize((cJSON *)sections) == 0 || !output || output_size == 0) {
        ESP_LOGE(TAG, "selected info json: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    root = cJSON_CreateObject();
    if (!root) {
        ESP_LOGE(TAG, "selected info json: create failed");
        return ESP_ERR_NO_MEM;
    }

    // Keep section names aligned with the LLM schema enum to avoid ambiguous tool behavior.
    if (cap_system_section_is_requested(sections, "chip")) {
        ESP_GOTO_ON_ERROR(cap_system_add_chip_section(root), cleanup, TAG, "Failed to add chip section");
    }
    if (cap_system_section_is_requested(sections, "uptime")) {
        ESP_GOTO_ON_ERROR(cap_system_add_uptime_section(root), cleanup, TAG, "Failed to add uptime section");
    }
    if (cap_system_section_is_requested(sections, "version")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "version", cap_system_build_version_json), cleanup, TAG, "Failed to add version section");
    }
    if (cap_system_section_is_requested(sections, "memory")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "memory", cap_system_build_memory_json), cleanup, TAG, "Failed to add memory section");
    }
    // cpu and tasks share one sampling window.
    if (cap_system_section_is_requested(sections, "cpu") || cap_system_section_is_requested(sections, "tasks")) {
        cap_system_cpu_sample_take(&sample);
    }
    if (cap_system_section_is_requested(sections, "cpu")) {
        ESP_GOTO_ON_ERROR(cap_system_add_section(root, "cpu", cap_system_build_cpu_json(&sample)), cleanup, TAG, "Failed to add cpu section");
    }
    if (cap_system_section_is_requested(sections, "tasks")) {
        ESP_GOTO_ON_ERROR(cap_system_add_section(root, "tasks", cap_system_build_tasks_json(&sample)), cleanup, TAG, "Failed to add tasks section");
    }
    if (cap_system_section_is_requested(sections, "wifi")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "wifi", cap_system_build_wifi_json), cleanup, TAG, "Failed to add wifi section");
    }
    if (cap_system_section_is_requested(sections, "ip")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "ip", cap_system_build_ip_json), cleanup, TAG, "Failed to add ip section");
    }
    if (cap_system_section_is_requested(sections, "reset")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "reset", cap_system_build_reset_json), cleanup, TAG, "Failed to add reset section");
    }
    if (cap_system_section_is_requested(sections, "storage")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "storage", cap_system_build_storage_json), cleanup, TAG, "Failed to add storage section");
    }
    if (cap_system_section_is_requested(sections, "temperature")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "temperature", cap_system_build_temperature_json), cleanup, TAG, "Failed to add temperature section");
    }
    if (cap_system_section_is_requested(sections, "network")) {
        ESP_GOTO_ON_ERROR(cap_system_add_json_section(root, "network", cap_system_build_network_json), cleanup, TAG, "Failed to add network section");
    }
    if (cap_system_section_is_requested(sections, "claw")) {
        ESP_GOTO_ON_ERROR(cap_system_add_section(root, "claw", cap_system_build_claw_json(ctx)), cleanup, TAG, "Failed to add claw section");
    }

    if (cJSON_GetArraySize(root) == 0) {
        ESP_LOGE(TAG, "selected info json: no known sections requested");
        snprintf(output, output_size, "{\"ok\":false,\"error\":\"no known sections requested\"}");
        ret = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    ret = cap_system_render_json(root, output, output_size);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "selected info json render failed: %s", esp_err_to_name(ret));
    }

cleanup:
    cap_system_cpu_sample_free(&sample);
    cJSON_Delete(root);
    return ret;
}

static esp_err_t cap_system_write_json(cJSON *(*builder)(void), char *output, size_t output_size)
{
    cJSON *root = NULL;
    esp_err_t err;

    if (!builder || !output || output_size == 0) {
        ESP_LOGE(TAG, "write json: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    root = builder();
    if (!root) {
        ESP_LOGE(TAG, "write json: build failed");
        return ESP_ERR_NO_MEM;
    }

    err = cap_system_render_json(root, output, output_size);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "write json failed: %s", esp_err_to_name(err));
    }
    return err;
}

static void cap_system_restart_task(void *arg)
{
    cap_system_restart_task_args_t *task_args = (cap_system_restart_task_args_t *)arg;
    uint32_t delay_ms = task_args ? task_args->delay_ms : CAP_SYSTEM_RESTART_DEFAULT_DELAY_MS;

    free(task_args);
    vTaskDelay(pdMS_TO_TICKS(delay_ms));
    esp_restart();
}

static esp_err_t cap_system_get_info_json(char *output, size_t output_size)
{
    esp_err_t err = cap_system_write_json(cap_system_build_info_json, output, output_size);

    if (err == ESP_OK) {
        CAP_SYSTEM_DEBUG_LOG("system_info", output);
    }

    return err;
}

static esp_err_t cap_system_get_selected_info_json(const char *input_json,
                                                   const claw_cap_call_context_t *ctx,
                                                   char *output,
                                                   size_t output_size)
{
    cJSON *input = NULL;
    cJSON *sections = NULL;
    esp_err_t err = ESP_OK;

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "get selected info: invalid output");
        return ESP_ERR_INVALID_ARG;
    }

    if (!input_json || !input_json[0]) {
        return cap_system_get_info_json(output, output_size);
    }

    input = cJSON_Parse(input_json);
    if (!input || !cJSON_IsObject(input)) {
        ESP_LOGE(TAG, "get selected info: invalid json");
        cJSON_Delete(input);
        snprintf(output, output_size, "{\"ok\":false,\"error\":\"invalid input json\"}");
        return ESP_ERR_INVALID_ARG;
    }

    sections = cJSON_GetObjectItem(input, "sections");
    if (!sections) {
        err = cap_system_get_info_json(output, output_size);
        goto cleanup;
    }
    if (!cJSON_IsArray(sections) || cJSON_GetArraySize(sections) == 0) {
        ESP_LOGE(TAG, "get selected info: invalid sections");
        snprintf(output, output_size, "{\"ok\":false,\"error\":\"sections must be a non-empty array\"}");
        err = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    err = cap_system_build_selected_info_json(sections, ctx, output, output_size);

    if (err == ESP_OK) {
        CAP_SYSTEM_DEBUG_LOG("selected_system_info", output);
    }

cleanup:
    cJSON_Delete(input);
    return err;
}

static esp_err_t cap_system_restart_async(uint32_t delay_ms)
{
    cap_system_restart_task_args_t *task_args = NULL;
    BaseType_t ok;

    if (delay_ms == 0) {
        delay_ms = CAP_SYSTEM_RESTART_DEFAULT_DELAY_MS;
    }

    task_args = calloc(1, sizeof(*task_args));
    if (!task_args) {
        ESP_LOGE(TAG, "restart args: no mem");
        return ESP_ERR_NO_MEM;
    }
    task_args->delay_ms = delay_ms;

    // Restart is deferred to let the current response flush out first.
    ok = claw_task_create(&(claw_task_config_t){
                              .name = "cap_system_restart",
                              .stack_size = 3072,
                              .priority = 5,
                              .core_id = tskNO_AFFINITY,
                              .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                          },
                          cap_system_restart_task,
                          task_args,
                          NULL);
    if (ok != pdPASS) {
        free(task_args);
        ESP_LOGE(TAG, "restart task create failed");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGW(TAG, "Device restart scheduled in %" PRIu32 " ms", delay_ms);
    return ESP_OK;
}

static esp_err_t cap_system_get_current_time(char *output, size_t output_size)
{
    esp_err_t err;

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "get current time: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_RETURN_ON_ERROR(cap_system_ensure_time_mutex(), TAG, "Failed to create time mutex");
    xSemaphoreTake(s_time_mutex, portMAX_DELAY);
    err = cap_system_is_time_valid() ? cap_system_format_current_time(output, output_size) : cap_system_sync_with_sntp(output, output_size);
    xSemaphoreGive(s_time_mutex);
    return err;
}

static esp_err_t cap_system_sync_time_now(char *output, size_t output_size)
{
    esp_err_t err;

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "sync time now: invalid arg");
        return ESP_ERR_INVALID_ARG;
    }

    ESP_RETURN_ON_ERROR(cap_system_ensure_time_mutex(), TAG, "Failed to create time mutex");
    xSemaphoreTake(s_time_mutex, portMAX_DELAY);
    err = cap_system_sync_with_sntp(output, output_size);
    xSemaphoreGive(s_time_mutex);
    return err;
}

static bool cap_system_is_time_valid(void)
{
    time_t now = time(NULL);

    return now >= CAP_SYSTEM_MIN_VALID_EPOCH;
}

esp_err_t cap_system_time_sync_service_start(const cap_system_time_sync_service_config_t *config)
{
    BaseType_t ok;

    if (!config) {
        ESP_LOGE(TAG, "time sync service start: invalid config");
        return ESP_ERR_INVALID_ARG;
    }
    if (s_time_service.task_handle || s_time_service.running) {
        return ESP_OK;
    }

    memset(&s_time_service.config, 0, sizeof(s_time_service.config));
    s_time_service.config = *config;
    if (s_time_service.config.disconnected_retry_ms == 0) {
        s_time_service.config.disconnected_retry_ms = CAP_SYSTEM_DEFAULT_DISCONNECTED_RETRY_MS;
    }
    if (s_time_service.config.sync_retry_ms == 0) {
        s_time_service.config.sync_retry_ms = CAP_SYSTEM_DEFAULT_SYNC_RETRY_MS;
    }

    if (cap_system_is_time_valid()) {
        cap_system_notify_time_sync_success(false);
        return ESP_OK;
    }

    s_time_service.running = true;
    ok = claw_task_create(&(claw_task_config_t){
                              .name = "cap_system_time_sync",
                              .stack_size = 4096,
                              .priority = 5,
                              .core_id = tskNO_AFFINITY,
                              .stack_policy = CLAW_TASK_STACK_PREFER_PSRAM,
                          }, cap_system_time_sync_service_task, NULL, &s_time_service.task_handle);
    if (ok != pdPASS || !s_time_service.task_handle) {
        s_time_service.running = false;
        s_time_service.task_handle = NULL;
        ESP_LOGE(TAG, "time sync service start: task create failed");
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

static esp_err_t cap_system_execute_get_info(const char *input_json,
                                             const claw_cap_call_context_t *ctx,
                                             char *output,
                                             size_t output_size)
{
    return cap_system_get_selected_info_json(input_json, ctx, output, output_size);
}

static esp_err_t cap_system_execute_get_current_time(const char *input_json,
                                                     const claw_cap_call_context_t *ctx,
                                                     char *output,
                                                     size_t output_size)
{
    esp_err_t err;

    (void)input_json;
    (void)ctx;

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "get current time cmd: invalid output");
        return ESP_ERR_INVALID_ARG;
    }

    err = cap_system_get_current_time(output, output_size);
    if (err != ESP_OK) {
        snprintf(output, output_size, "Error: failed to get time (%s)", esp_err_to_name(err));
        ESP_LOGE(TAG, "%s", output);
        return err;
    }

    ESP_LOGI(TAG, "Current time: %s", output);
    return ESP_OK;
}

static esp_err_t cap_system_execute_restart(const char *input_json,
                                            const claw_cap_call_context_t *ctx,
                                            char *output,
                                            size_t output_size)
{
    cJSON *input = NULL;
    cJSON *delay_item = NULL;
    uint32_t delay_ms = CAP_SYSTEM_RESTART_DEFAULT_DELAY_MS;
    esp_err_t err;

    (void)ctx;

    if (!output || output_size == 0) {
        ESP_LOGE(TAG, "restart cmd: invalid output");
        return ESP_ERR_INVALID_ARG;
    }

    if (input_json && input_json[0]) {
        input = cJSON_Parse(input_json);
        if (!input || !cJSON_IsObject(input)) {
            ESP_LOGE(TAG, "restart cmd: invalid json");
            cJSON_Delete(input);
            snprintf(output, output_size, "{\"ok\":false,\"error\":\"invalid input json\"}");
            return ESP_ERR_INVALID_ARG;
        }

        delay_item = cJSON_GetObjectItem(input, "delay_ms");
        if (cJSON_IsNumber(delay_item) && delay_item->valuedouble >= 0) {
            delay_ms = (uint32_t)delay_item->valuedouble;
        }
    }

    err = cap_system_restart_async(delay_ms);
    cJSON_Delete(input);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "restart schedule failed: %s", esp_err_to_name(err));
        snprintf(output,
                 output_size,
                 "{\"ok\":false,\"error\":\"failed to schedule restart\",\"code\":\"%s\"}",
                 esp_err_to_name(err));
        return err;
    }

    snprintf(output,
             output_size,
             "{\"ok\":true,\"message\":\"device restart scheduled\",\"delay_ms\":%" PRIu32 "}",
             delay_ms);
    return ESP_OK;
}

static const claw_cap_descriptor_t s_system_descriptors[] = {
    {
        .id = "get_system_info",
        .name = "get_system_info",
        .family = "system",
        .description = "Get live device status: chip, uptime, version, memory, cpu, tasks, wifi, ip, network, reset, "
                       "storage, temperature, claw. Omit sections for a summary (no tasks/temperature/network/claw). "
                       "**You cannot speculate or fabricate information.**",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"sections\":{\"type\":\"array\",\"items\":{\"type\":\"string\","
                             "\"enum\":[\"chip\",\"uptime\",\"version\",\"memory\",\"cpu\",\"tasks\",\"wifi\",\"ip\",\"network\","
                             "\"reset\",\"storage\",\"temperature\",\"claw\"]},\"minItems\":1,\"uniqueItems\":true,"
                             "\"description\":\"Optional sections; omit for a summary. memory: heap/PSRAM/DMA free, min-ever, largest block. "
                             "cpu: per-core load over 500 ms. tasks: top 25 tasks by CPU with stack headroom, for performance or crash debugging. "
                             "wifi: RSSI, channel, PHY, disconnects, soft-AP clients. network: sockets, gateway, DNS. "
                             "reset: last reset reason, boot count, core dump. storage: filesystem, inbox, NVS, app partition. "
                             "temperature: chip temperature. claw: capabilities, skills, Lua jobs, sub-agents.\"}}}",
        .execute = cap_system_execute_get_info,
    },
    {
        .id = "get_current_time",
        .name = "get_current_time",
        .family = "system",
        .description = "Return formatted current local time. Sync with SNTP only when the clock is invalid.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{}}",
        .execute = cap_system_execute_get_current_time,
    },
    {
        .id = "restart_device",
        .name = "restart_device",
        .family = "system",
        .description = "Schedule a device restart after an optional delay in milliseconds.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_CALLABLE_BY_LLM,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"delay_ms\":{\"type\":\"integer\",\"minimum\":0}}}",
        .execute = cap_system_execute_restart,
    },
    {
        .id = "storage_command",
        .name = "storage_command",
        .family = "system",
        .description = "Handle restricted /storage status, preview, cleanup and memory-index checks.",
        .kind = CLAW_CAP_KIND_CALLABLE,
        .cap_flags = CLAW_CAP_FLAG_RESTRICTED,
        .input_schema_json = "{\"type\":\"object\",\"properties\":{\"command\":{\"type\":\"string\"}}}",
        .execute = cap_system_storage_execute,
    },
};

static const claw_cap_group_t s_system_group = {
    .group_id = "cap_system",
    .descriptors = s_system_descriptors,
    .descriptor_count = sizeof(s_system_descriptors) / sizeof(s_system_descriptors[0]),
};

static void cap_system_wifi_disconnected_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    (void)base;
    (void)id;
    (void)data;
    s_wifi_disconnect_count++;
}

static void cap_system_record_boot(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(CAP_SYSTEM_STATS_NVS_NAMESPACE, NVS_READWRITE, &handle);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "boot count: nvs open failed: %s", esp_err_to_name(err));
        return;
    }

    nvs_get_u32(handle, CAP_SYSTEM_BOOT_COUNT_KEY, &s_boot_count);
    s_boot_count++;
    err = nvs_set_u32(handle, CAP_SYSTEM_BOOT_COUNT_KEY, s_boot_count);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "boot count: nvs write failed: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
}

esp_err_t cap_system_register_group(void)
{
    esp_err_t err;

    if (claw_cap_group_exists(s_system_group.group_id)) {
        return ESP_OK;
    }

    err = cap_system_storage_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "storage command init failed: %s", esp_err_to_name(err));
        return err;
    }

    // Registration runs once per boot, after NVS and the default event loop are up.
    if (s_boot_count == 0) {
        cap_system_record_boot();
    }
    if (!s_wifi_disconnect_handler &&
            esp_event_handler_instance_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
                                                cap_system_wifi_disconnected_handler, NULL,
                                                &s_wifi_disconnect_handler) != ESP_OK) {
        ESP_LOGW(TAG, "wifi disconnect counter unavailable");
    }

    err = claw_cap_register_group(&s_system_group);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "register group failed: %s", esp_err_to_name(err));
    } else if (cap_system_storage_start_monitor() != ESP_OK) {
        ESP_LOGW(TAG, "storage low-space monitor unavailable");
    }

    return err;
}
