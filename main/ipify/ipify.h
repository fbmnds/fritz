
#ifndef _IPIFY_H_
#define _IPIFY_H_

#include "freertos/FreeRTOS.h"

extern bool connected;
extern char ip[];

extern const uint8_t ipifyorg_pem_start[] asm("_binary_ipifyorg_pem_start");
extern const uint8_t ipifyorg_pem_end[] asm("_binary_ipifyorg_pem_end");

/* Constants that aren't configurable in menuconfig */
#define IPIFY_SERVER "api.ipify.org"
#define IPIFY_PORT   "443"
#define IPIFY_URL    "https://api.ipify.org"


static const char *REQUEST = "GET / HTTP/1.1\r\n"
    "Host: "IPIFY_SERVER"\r\n"
    "Connection: Close\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
"\r\n";


static void ipify_task(void *pvParameters)
{
    char buf[512];
    int ret, len;
    esp_tls_cfg_t cfg = {
        .cacert_pem_buf  = ipifyorg_pem_start,
        .cacert_pem_bytes = ipifyorg_pem_end - ipifyorg_pem_start,
    };

    while(1) {
        if (connected == false) {
            ESP_LOGI("ipify", "not connected");
            goto retry;
        }
        struct esp_tls *tls = esp_tls_conn_http_new(IPIFY_URL, &cfg);

        if(tls != NULL) {
            ESP_LOGI("ipify", "Connection established...");
        } else {
            ESP_LOGE("ipify", "Connection failed...");
            goto loop;
        }

        size_t written_bytes = 0;
        do {
            ret = esp_tls_conn_write(tls,
                                     REQUEST + written_bytes,
                                     strlen(REQUEST) - written_bytes);
            if (ret >= 0) {
                ESP_LOGI("ipify", "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ESP_LOGE("ipify", "esp_tls_conn_write  returned 0x%x", ret);
                goto loop;
            }
        } while(written_bytes < strlen(REQUEST));

        ESP_LOGI("ipify", "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = esp_tls_conn_read(tls, (char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
                continue;

            if(ret < 0)
           {
                ESP_LOGE("ipify", "esp_tls_conn_read  returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI("ipify", "connection closed");
                break;
            }

            len = ret;
            ESP_LOGI("ipify", "%d bytes read", len);
            /* Print response directly to stdout as it is read */

            if (len > 120) {
                buf[15] = '\0';
                if  (!strcmp(buf,"HTTP/1.1 200 OK")) {
                    int j = 0;
                    for(int i = len - 16; i < len; i++) {
                        if ((buf[i] >='0' && buf[i] <= '9') || buf[i] == '.') {
                            ip[j] = buf[i];
                            j++;
                        }
                    }
                }
            }

            ESP_LOGI("ipify", "ip: %s", ip);

        } while(1);

    loop:
        esp_tls_conn_delete(tls);

        //putchar('\n'); // JSON output doesn't have a newline at end

        //static int request_count;
        //ESP_LOGI("ipify", "Completed %d requests", ++request_count);
        vTaskDelay((60*60*1000) / portTICK_PERIOD_MS);
        break;

    retry:
        vTaskDelay((5*1000) / portTICK_PERIOD_MS);

    }
}


#endif