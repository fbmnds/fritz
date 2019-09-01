#ifndef _TELEGRAM_H_
#define _TELEGRAM_H_

// https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>&text=Hello%20World


#include "freertos/FreeRTOS.h"
#include "stdio.h"

#include "../secrets/secrets.h"

extern bool connected;
extern char ip[];
static char prev_ip[] = "___.___.___.___";

extern bool renew_api_key;

extern const uint8_t telegram_pem_start[] asm("_binary_telegram_pem_start");
extern const uint8_t telegram_pem_end[] asm("_binary_telegram_pem_end");

/* Constants that aren't configurable in menuconfig */
#define TELEGRAM_SERVER   "api.telegram.org"
#define TELEGRAM_PORT     "443"
#define TELEGRAM_URL      "/bot"BOT_TOKEN"/sendMessage?chat_id="BOT_ID
#define TELEGRAM_TAG      "telegram"
#define TELEGRAM_PRIORITY HTTP_TASK_PRIORITY+1

static const char *T_REQUEST = "POST "TELEGRAM_URL" HTTP/1.1\r\n"
    "Host: "TELEGRAM_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "Accept: */*\r\n"
    "Content-Length: %d\r\n"
    "Content-Type: application/x-www-form-urlencoded\n\r\n"
    "text=%s";
#define TEXT_EQ_LEN 5

static void telegram_task(void *pvParameters)
{
    char *temp_buf;
    char request[1536];
    int request_len;
    char buf_hex[1024];
    char buf[512];
    int ret, len, buf_len, buf_hex_len;

    const esp_tls_cfg_t cfg = {
        /*
        .cacert_pem_buf   = telegram_pem_start,
        .cacert_pem_bytes = telegram_pem_end - telegram_pem_start
        */
    };
    ESP_LOGI(TELEGRAM_TAG, "init");

    while(1) {
        temp_buf = strstr(ip, "___.___.___.___");
        if (temp_buf) {
            goto retry;
        }

        temp_buf = strstr(ip, prev_ip);
        if (temp_buf && !renew_api_key) goto loop2;
        
        bzero(prev_ip,sizeof(prev_ip));
        strcpy(prev_ip, ip);
        set_api_key();
        renew_api_key = false;

        if (connected == false) {
            ESP_LOGI(TELEGRAM_TAG, "not connected");
            goto retry;
        }
        sprintf(request, "https://%s%s", TELEGRAM_SERVER, TELEGRAM_URL);
        ESP_LOGI(TELEGRAM_TAG, "requested url: %s", request);

        struct esp_tls *tls = esp_tls_conn_http_new(request, &cfg);

        if(tls != NULL) {
            ESP_LOGI(TELEGRAM_TAG, "Connection established...");
        } else {
            ESP_LOGE(TELEGRAM_TAG, "Connection failed...");
            goto loop;
        }

        for (int i=0; i<strlen(ip); i++) buf[i] = ip[i];
        buf[strlen(ip)]=';';
        buf_len = strlen(ip)+1+strlen(API_KEY);

        for (int i=strlen(ip)+1; i<buf_len; i++) buf[i] = API_KEY[i-strlen(ip)-1];
        buf[buf_len] = '\0';
        
        aes128_cbc_encrypt(buf, buf_len, buf_hex, &buf_hex_len);

        //sprintf(request, T_REQUEST, TEXT_EQ_LEN + strlen(buf_hex), buf_hex);
        sprintf(request, T_REQUEST, TEXT_EQ_LEN + buf_hex_len - 1, buf_hex);
        request_len = strlen(request);
        ESP_LOGI(TELEGRAM_TAG, "request: %s", request);

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
            ESP_LOGI(TELEGRAM_TAG, "%s", buf);

        } while(1);

    loop:
        esp_tls_conn_delete(tls);
    loop2:
        vTaskDelay((5*1000) / portTICK_PERIOD_MS);
        continue;

    retry:
        vTaskDelay((5*1000) / portTICK_PERIOD_MS);
    }
}



#endif