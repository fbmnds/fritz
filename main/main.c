/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include "openssl_server.h"

#include <string.h>
#include <stdlib.h>

#include "driver/gpio.h"

#include "openssl/ssl.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_system.h"

#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include <cJSON.h>

#include "esp_tls.h"


static bool connected = false;

static EventGroupHandle_t wifi_event_group;

static char ip[512];

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const static int CONNECTED_BIT = BIT0;

const static char *TAG = "relay";

#define PIN_1 GPIO_NUM_12
#define PIN_2 GPIO_NUM_14
#define PIN_3 GPIO_NUM_27
#define PIN_4 GPIO_NUM_26


#define TLS_SERVER_ACK "HTTP/1.1 200 OK\r\n"

#define TLS_SERVER_ACK_1 "HTTP/1.1 200 OK\r\n" \
                         "Content-Type: text/plain\r\n" \
                         "Content-Length: 15\r\n\r\n" \
                         "_______________" \
                         "\r\n"

#define ACK_1_OFFSET 61

static void tls_task(void *p)
{
    int ret;

    SSL_CTX *ctx;
    SSL *ssl;

    int sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    char recv_buf[TLS_RECV_BUF_LEN];

    const char send_data[] = TLS_SERVER_ACK;
    const int send_bytes = sizeof(send_data);

    char send_data_1[] = TLS_SERVER_ACK_1;
    const int send_bytes_1 = sizeof(send_data_1);
    char ip[512];

    extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");
    extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
    const unsigned int cacert_pem_bytes = cacert_pem_end - cacert_pem_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    const unsigned int prvtkey_pem_bytes = prvtkey_pem_end - prvtkey_pem_start;

    ESP_LOGI(TAG, "SSL server context create ......");
    /* For security reasons, it is best if you can use
       TLSv1_2_server_method() here instead of TLS_server_method().
       However some old browsers may not support TLS v1.2.
    */
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (!ctx) {
        ESP_LOGI(TAG, "failed");
        goto failed1;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server context set own certification......");
    ret = SSL_CTX_use_certificate_ASN1(ctx, cacert_pem_bytes, cacert_pem_start);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server context set private key......");
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, prvtkey_pem_start, prvtkey_pem_bytes);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server create socket ......");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket bind ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(TLS_LOCAL_TCP_PORT);
    ret = bind(sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket listen ......");
    ret = listen(sockfd, 32);
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

reconnect:
    ESP_LOGI(TAG, "SSL server create ......");
    ssl = SSL_new(ctx);
    if (!ssl) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_len);
    if (new_sockfd < 0) {
        ESP_LOGI(TAG, "failed" );
        goto failed4;
    }
    ESP_LOGI(TAG, "OK");

    SSL_set_fd(ssl, new_sockfd);

    connected = true;

    ESP_LOGI(TAG, "SSL server accept client ......");
    ret = SSL_accept(ssl);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed5;
    }
    ESP_LOGI(TAG, "OK");


    ESP_LOGI(TAG, "SSL server read message ......");
    do {
        memset(recv_buf, 0, TLS_RECV_BUF_LEN);
        ret = SSL_read(ssl, recv_buf, TLS_RECV_BUF_LEN - 1);
        if (ret <= 0) {
            break;
        }

        ESP_LOGI(TAG, "SSL read: %s", recv_buf);


        if (strstr(recv_buf, "GET /1/on HTTP/1.1")) {
            gpio_set_level(PIN_1, 1);
        }
        else if (strstr(recv_buf, "GET /1/off HTTP/1.1")) {
            gpio_set_level(PIN_1, 0);
        }

        else if (strstr(recv_buf, "GET /2/on HTTP/1.1")) {
            gpio_set_level(PIN_2, 1);
        }
        else if (strstr(recv_buf, "GET /2/off HTTP/1.1")) {
            gpio_set_level(PIN_2, 0);
        }

        else if (strstr(recv_buf, "GET /3/on HTTP/1.1")) {;
            gpio_set_level(PIN_3, 1);
        }
        else if (strstr(recv_buf, "GET /3/off HTTP/1.1")) {
            gpio_set_level(PIN_3, 0);
        }

        else if (strstr(recv_buf, "GET /4/on HTTP/1.1")) {;
            gpio_set_level(PIN_4, 1);
        }
        else if (strstr(recv_buf, "GET /4/off HTTP/1.1")) {
            gpio_set_level(PIN_4, 0);
        }
/*
        ret = SSL_write(ssl, send_data, send_bytes);
        if (ret > 0) {
            ESP_LOGI(TAG, "OK");
        } else {
            ESP_LOGI(TAG, "error");
        }
        break;
*/
        else if (strstr(recv_buf, "GET /ip HTTP/1.1")) {
            for (int i=0; i<16; i++) {
                if ((ip[i] >= '0' && ip[i] <= '9') || ip[i] == '.') {
                    send_data_1[ACK_1_OFFSET+i] = ip[i];
                }
            }
            ESP_LOGI(TAG, "IP: %s", send_data_1);
        }

        ESP_LOGI(TAG, "IP: %s", send_data_1);
        ret = SSL_write(ssl, send_data_1, send_bytes_1);
        if (ret > 0) {
            ESP_LOGI(TAG, "OK");
        } else {
            ESP_LOGI(TAG, "error");
        }
        break;
/*
        ret = SSL_write(ssl, send_data, send_bytes);
        if (ret > 0) {
            ESP_LOGI(TAG, "OK");
        } else {
            ESP_LOGI(TAG, "error");
        }
        break;
*/
    } while (1);

    SSL_shutdown(ssl);
failed5:
    close(new_sockfd);
    new_sockfd = -1;
failed4:
    SSL_free(ssl);
    ssl = NULL;
    taskYIELD();
    goto reconnect;
failed3:
    close(sockfd);
    sockfd = -1;
failed2:
    SSL_CTX_free(ctx);
    ctx = NULL;
failed1:
    vTaskDelete(NULL);
    return ;
}

static void openssl_server_init(void)
{
    int ret;
    xTaskHandle openssl_handle;

    ret = xTaskCreate(tls_task,
                      TLS_TASK_NAME,
                      TLS_TASK_STACK_WORDS,
                      NULL,
                      TLS_TASK_PRIORITY,
                      &openssl_handle);

    if (ret != pdPASS)  {
        ESP_LOGI(TAG, "create task %s failed", TLS_TASK_NAME);
    }
}

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        openssl_server_init();
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        ESP_LOGI(TAG, "got event_id: %d", event->event_id);
        break;
    }
    return ESP_OK;
}

static void wifi_conn_init(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(wifi_event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_LOGI(TAG, "start the WIFI SSID:[%s] password:[%s]\n", EXAMPLE_WIFI_SSID, EXAMPLE_WIFI_PASS);
    ESP_ERROR_CHECK( esp_wifi_start() );
}




extern const uint8_t ipifyorg_pem_start[] asm("_binary_ipifyorg_pem_start");
extern const uint8_t ipifyorg_pem_end[] asm("_binary_ipifyorg_pem_end");

/* Constants that aren't configurable in menuconfig */
#define WEB_SERVER "api.ipify.org"
#define WEB_PORT "443"
#define WEB_URL "https://api.ipify.org"

static const char *REQUEST = "GET / HTTP/1.1\r\n"
    "Host: "WEB_SERVER"\r\n"
    "Connection: Close\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
"\r\n";




static void ipify_task(void *pvParameters)
{
    char buf[512];
    int ret, len;

    while(1) {
        esp_tls_cfg_t cfg = {
            .cacert_pem_buf  = ipifyorg_pem_start,
            .cacert_pem_bytes = ipifyorg_pem_end - ipifyorg_pem_start,
        };

        if (connected == false) {
            ESP_LOGI("ipify", "not connected");
            goto next;
        }
        struct esp_tls *tls = esp_tls_conn_http_new(WEB_URL, &cfg);

        if(tls != NULL) {
            ESP_LOGI("ipify", "Connection established...");
        } else {
            ESP_LOGE("ipify", "Connection failed...");
            goto exit;
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
                goto exit;
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
            for(int i = 0; i < len; i++) {
                ip[i] = buf[i];
            }
            ESP_LOGI("ipify", "ip: %s", ip);

        } while(1);

    exit:
        esp_tls_conn_delete(tls);

        putchar('\n'); // JSON output doesn't have a newline at end

        //static int request_count;
        //ESP_LOGI("ipify", "Completed %d requests", ++request_count);

    next:
        vTaskDelay((3*60*1000) / portTICK_PERIOD_MS);

    }
}


void app_main(void)
{
    uint8_t mac[6] = { 0x80, 0x7D, 0x3A, 0x80, 0, 2 };
    esp_base_mac_addr_set(mac);


    gpio_pad_select_gpio(PIN_1);
    gpio_pad_select_gpio(PIN_2);
    gpio_pad_select_gpio(PIN_3);
    gpio_pad_select_gpio(PIN_4);

    gpio_set_direction(PIN_1, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_2, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_3, GPIO_MODE_OUTPUT);
    gpio_set_direction(PIN_4, GPIO_MODE_OUTPUT);

    gpio_set_level(PIN_1, 0);
    gpio_set_level(PIN_2, 0);
    gpio_set_level(PIN_3, 0);
    gpio_set_level(PIN_4, 0);

    ESP_ERROR_CHECK( nvs_flash_init() );
    wifi_conn_init();

    vTaskStartScheduler();

    xTaskCreate(&ipify_task, "ipify_task", 8192, NULL, 5, NULL);

}
