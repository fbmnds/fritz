#ifndef _TELEGRAM_H_
#define _TELEGRAM_H_

// https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=Hello%20World


#include "freertos/FreeRTOS.h"

#include "../secrets/secrets.h"

extern bool connected;
extern char ip[];
static char prev_ip[] = "___.___.___.___";

extern const uint8_t telegram_pem_start[] asm("_binary_telegram_pem_start");
extern const uint8_t telegram_pem_end[] asm("_binary_telegram_pem_end");

/* Constants that aren't configurable in menuconfig */
#define TELEGRAM_SERVER   "api.telegram.org"
#define TELEGRAM_PORT     "443"
#define TELEGRAM_URL      "/bot"BOT_TOKEN"/sendMessage?chat_id="BOT_ID"&text="
#define TELEGRAM_TAG      "telegram"
#define TELEGRAM_PRIORITY TLS_TASK_PRIORITY+1

static const char *T_REQUEST = "GET "TELEGRAM_URL"%s HTTP/1.1\r\n"
    "Host: "TELEGRAM_SERVER"\r\n"
    "Connection: Close\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
"\r\n";

static void telegram_task(void *pvParameters)
{
    char *temp_buf;
    char request[300];
    int request_len;
    char buf[512];
    int ret, len;
    esp_tls_cfg_t cfg = {
        .cacert_pem_buf   = telegram_pem_start,
        .cacert_pem_bytes = telegram_pem_end - telegram_pem_start,
    };

    while(1) {
        temp_buf = strstr(ip, "___.___.___.___");
        if (temp_buf) {
            goto retry;
        }

        temp_buf = strstr(ip, prev_ip);
        if (temp_buf) {
            goto loop2;
        } else {
            strcpy(prev_ip, ip);
        }

        if (connected == false) {
            ESP_LOGI(TELEGRAM_TAG, "not connected");
            goto retry;
        }
        sprintf(request, "%s%s", TELEGRAM_URL, ip);
        struct esp_tls *tls = esp_tls_conn_http_new(request, &cfg);

        if(tls != NULL) {
            ESP_LOGI(TELEGRAM_TAG, "Connection established...");
        } else {
            ESP_LOGE(TELEGRAM_TAG, "Connection failed...");
            goto loop;
        }

        sprintf(request, T_REQUEST, ip);
        request_len = strlen(request);

        size_t written_bytes = 0;
        do {
            ret = esp_tls_conn_write(tls,
                                     request + written_bytes,
                                     request_len - written_bytes);
            if (ret >= 0) {
                ESP_LOGI(TELEGRAM_TAG, "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ESP_LOGE(TELEGRAM_TAG, "esp_tls_conn_write  returned 0x%x", ret);
                goto loop;
            }
        } while(written_bytes < request_len);

        ESP_LOGI(TELEGRAM_TAG, "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = esp_tls_conn_read(tls, (char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
                continue;

            if(ret < 0)
            {
                ESP_LOGE(TELEGRAM_TAG, "esp_tls_conn_read  returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TELEGRAM_TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGI(TELEGRAM_TAG, "%d bytes read", len);

        } while(1);

    loop:
        esp_tls_conn_delete(tls);
    loop2:
        vTaskDelay((60*60*1000) / portTICK_PERIOD_MS);
        continue;

    retry:
        vTaskDelay((5*1000) / portTICK_PERIOD_MS);

    }
}



#endif