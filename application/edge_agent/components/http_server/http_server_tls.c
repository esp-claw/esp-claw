/*
 * SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/*
 * HTTPS server with a self-signed ECDSA P-256 certificate, generated on first start and kept in NVS
 * (namespace http_tls; the key never leaves it except into the TLS stack). It names the hostname,
 * <hostname>.local and the STA and soft-AP addresses of that moment; /web cert renew makes a new one.
 */
#include "http_server_priv.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"

#define TLS_NVS_NS         "http_tls"
#define TLS_CERT_MAX       1024
#define TLS_KEY_MAX        256
#define TLS_VALID_DAYS     825 /* the longest validity Apple platforms accept for TLS server certificates */
#define TLS_TASK_STACK     8192
#define HTTPS_MAX_SESSIONS 2

static const char *TAG = "http_tls";

typedef struct {
    uint8_t cert[TLS_CERT_MAX];
    uint8_t key[TLS_KEY_MAX];
    size_t cert_len;
    size_t key_len;
    char names[sizeof(((http_server_ctx_t *)0)->cert_names)];
    uint64_t until;
} tls_material_t;

typedef struct {
    bool renew;
    esp_err_t ret;
    SemaphoreHandle_t done;
    StaticSemaphore_t done_buf;
} tls_job_t;

static int tls_rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

/* The clock once SNTP has set it, else the firmware build time. */
static time_t tls_now(void)
{
    const esp_app_desc_t *app = esp_app_get_description();
    struct tm tm = {0};
    char built[40];
    time_t now = time(NULL);
    time_t build_time;

    snprintf(built, sizeof(built), "%s %s", app->date, app->time);
    build_time = strptime(built, "%b %d %Y %H:%M:%S", &tm) ? mktime(&tm) : 0;
    return build_time > now ? build_time : now;
}

static int tls_generate(tls_material_t *m)
{
    static const char *const ifkeys[] = {"WIFI_STA_DEF", "WIFI_AP_DEF"};
    const char *host = CONFIG_LWIP_LOCAL_HOSTNAME;
    char local[sizeof(CONFIG_LWIP_LOCAL_HOSTNAME) + 6];
    char cn[sizeof(local) + 3];
    char not_before[16];
    char not_after[16];
    uint8_t ips[2][4];
    uint8_t serial[16];
    mbedtls_x509_san_list san[4] = {0};
    mbedtls_asn1_sequence eku = {
        .buf = {
            .tag = MBEDTLS_ASN1_OID,
            .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH),
            .p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH,
        },
    };
    mbedtls_pk_context pk;
    mbedtls_x509write_cert crt;
    esp_netif_ip_info_t info;
    time_t start = tls_now();
    time_t end = start + TLS_VALID_DAYS * 86400LL;
    struct tm tm;
    size_t count = 0;
    int ret;

    snprintf(local, sizeof(local), "%s.local", host);
    snprintf(cn, sizeof(cn), "CN=%s", local);
    snprintf(m->names, sizeof(m->names), "%s, %s", host, local);
    for (size_t i = 0; i < 2; i++) {
        san[count].node.type = MBEDTLS_X509_SAN_DNS_NAME;
        san[count].node.san.unstructured_name.p = (unsigned char *)(i ? local : host);
        san[count].node.san.unstructured_name.len = strlen(i ? local : host);
        count++;
    }
    for (size_t i = 0; i < sizeof(ifkeys) / sizeof(ifkeys[0]); i++) {
        if (http_server_netif_ip(ifkeys[i], &info)) {
            size_t len = strlen(m->names);

            memcpy(ips[i], &info.ip.addr, 4);
            san[count].node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
            san[count].node.san.unstructured_name.p = ips[i];
            san[count].node.san.unstructured_name.len = 4;
            count++;
            snprintf(m->names + len, sizeof(m->names) - len, ", " IPSTR, IP2STR(&info.ip));
        }
    }
    for (size_t i = 0; i + 1 < count; i++) {
        san[i].next = &san[i + 1];
    }
    strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", gmtime_r(&start, &tm));
    strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", gmtime_r(&end, &tm));
    esp_fill_random(serial, sizeof(serial));
    serial[0] = (serial[0] & 0x7f) | 0x40; /* positive, minimal DER integer */

    mbedtls_pk_init(&pk);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&crt, &pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk);
    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) == 0 &&
            (ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk), tls_rng, NULL)) == 0 &&
            (ret = mbedtls_x509write_crt_set_subject_name(&crt, cn)) == 0 &&
            (ret = mbedtls_x509write_crt_set_issuer_name(&crt, cn)) == 0 &&
            (ret = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial))) == 0 &&
            (ret = mbedtls_x509write_crt_set_validity(&crt, not_before, not_after)) == 0 &&
            (ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1)) == 0 &&
            (ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) == 0 &&
            (ret = mbedtls_x509write_crt_set_ext_key_usage(&crt, &eku)) == 0 &&
            (ret = mbedtls_x509write_crt_set_subject_alternative_name(&crt, san)) == 0 &&
            (ret = mbedtls_x509write_crt_der(&crt, m->cert, sizeof(m->cert), tls_rng, NULL)) > 0) {
        /* mbedtls writes DER at the end of the buffer. */
        m->cert_len = (size_t)ret;
        memmove(m->cert, m->cert + sizeof(m->cert) - m->cert_len, m->cert_len);
        ret = mbedtls_pk_write_key_der(&pk, m->key, sizeof(m->key));
    }
    if (ret > 0) {
        m->key_len = (size_t)ret;
        memmove(m->key, m->key + sizeof(m->key) - m->key_len, m->key_len);
        m->until = (uint64_t)end;
        ret = 0;
    }
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk);
    return ret;
}

/* The stored certificate, or a new one when there is none, it expired or `renew` asks for one. */
static esp_err_t tls_load(bool renew, tls_material_t *m)
{
    nvs_handle_t nvs;
    size_t cert_len = sizeof(m->cert);
    size_t key_len = sizeof(m->key);
    size_t names_len = sizeof(m->names);
    esp_err_t err = nvs_open(TLS_NVS_NS, NVS_READWRITE, &nvs);
    int ret;

    if (err != ESP_OK) {
        return err;
    }
    if (!renew && nvs_get_blob(nvs, "cert", m->cert, &cert_len) == ESP_OK &&
            nvs_get_blob(nvs, "key", m->key, &key_len) == ESP_OK &&
            nvs_get_str(nvs, "names", m->names, &names_len) == ESP_OK &&
            nvs_get_u64(nvs, "until", &m->until) == ESP_OK && (time_t)m->until > tls_now()) {
        m->cert_len = cert_len;
        m->key_len = key_len;
    } else if ((ret = tls_generate(m)) != 0) {
        ESP_LOGE(TAG, "Certificate generation failed: -0x%04x", (unsigned)-ret);
        err = ESP_FAIL;
    } else {
        ESP_LOGI(TAG, "New self-signed certificate for %s", m->names);
        err = nvs_set_blob(nvs, "key", m->key, m->key_len);
        err = err == ESP_OK ? nvs_set_blob(nvs, "cert", m->cert, m->cert_len) : err;
        err = err == ESP_OK ? nvs_set_str(nvs, "names", m->names) : err;
        err = err == ESP_OK ? nvs_set_u64(nvs, "until", m->until) : err;
        err = err == ESP_OK ? nvs_commit(nvs) : err;
    }
    nvs_close(nvs);
    return err;
}

static esp_err_t tls_start_server(bool renew)
{
    http_server_ctx_t *ctx = http_server_ctx();
    tls_material_t *m = heap_caps_calloc(1, sizeof(*m), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    uint8_t hash[32];
    time_t until;
    struct tm tm;
    esp_err_t err;

    if (!m) {
        return ESP_ERR_NO_MEM;
    }
    err = tls_load(renew, m);
    if (err == ESP_OK) {
        mbedtls_sha256(m->cert, m->cert_len, hash, 0);
        for (size_t i = 0; i < sizeof(hash); i++) {
            snprintf(ctx->cert_sha256 + 3 * i, sizeof(ctx->cert_sha256) - 3 * i, i ? ":%02X" : "%02X", hash[i]);
        }
        until = (time_t)m->until;
        strftime(ctx->cert_until, sizeof(ctx->cert_until), "%Y-%m-%d", gmtime_r(&until, &tm));
        strlcpy(ctx->cert_names, m->names, sizeof(ctx->cert_names));

        if (ctx->https) {
            httpd_ssl_stop(ctx->https);
            ctx->https = NULL;
        }
        http_server_httpd_config(&conf.httpd);
        conf.httpd.ctrl_port = HTTP_SERVER_CTRL_PORT + 1;
        conf.httpd.max_open_sockets = HTTPS_MAX_SESSIONS;
        conf.httpd.stack_size = 10240; /* TLS handshakes */
        conf.servercert = m->cert;
        conf.servercert_len = m->cert_len;
        conf.prvtkey_pem = m->key;
        conf.prvtkey_len = m->key_len;
        err = httpd_ssl_start(&ctx->https, &conf);
        if (err == ESP_OK) {
            err = http_server_register_routes(ctx->https);
        }
    }
    mbedtls_platform_zeroize(m, sizeof(*m));
    heap_caps_free(m);
    return err;
}

static void tls_start_task(void *arg)
{
    tls_job_t *job = arg;

    job->ret = tls_start_server(job->renew);
    xSemaphoreGive(job->done);
    vTaskDeleteWithCaps(NULL);
}

esp_err_t http_server_https_start(bool renew)
{
    tls_job_t job = { .renew = renew };

    /* Key generation and the TLS setup need more stack than the callers (main, Telegram poll) have. */
    job.done = xSemaphoreCreateBinaryStatic(&job.done_buf);
    if (xTaskCreateWithCaps(tls_start_task, "https_start", TLS_TASK_STACK, &job, uxTaskPriorityGet(NULL), NULL,
                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(job.done, portMAX_DELAY);
    return job.ret;
}
