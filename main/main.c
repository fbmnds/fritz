/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include "sdkconfig.h"
#include "openssl_server.h"

#include <string.h>
#include <stdlib.h>

#include <driver/gpio.h>

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

#include "secrets/secrets.h"

static bool connected = false;
static char ip[] = "___.___.___.___";
#include "ipify/ipify.h"
#include "telegram/telegram.h"


static bool ipify_created = false;
static bool telegram_created = false;
static EventGroupHandle_t wifi_event_group;

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
                         "___.___.___.___" \
                         "\r\n"

#define ACK_1_OFFSET 65

static void tls_task(void *p)
{
    int ret;

    SSL_CTX *ctx;
    SSL *ssl;

    int sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    char recv_buf[TLS_RECV_BUF_LEN];
    char *temp_buf;

    //const char send_data[] = TLS_SERVER_ACK;
    //const int send_bytes = sizeof(send_data);

    char send_data_1[] = TLS_SERVER_ACK_1;
    const int send_bytes_1 = sizeof(send_data_1);

    extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");
    extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
    const unsigned int cacert_pem_bytes = cacert_pem_end - cacert_pem_start;

    extern const unsigned char server_key_start[] asm("_binary_server_key_start");
    extern const unsigned char server_key_end[]   asm("_binary_server_key_end");
    const unsigned int server_key_bytes = server_key_end - server_key_start;

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
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, server_key_start, server_key_bytes);
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

    connected = true;

    ESP_LOGI(TAG, "SSL server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_len);
    if (new_sockfd < 0) {
        ESP_LOGI(TAG, "failed" );
        goto failed4;
    }
    ESP_LOGI(TAG, "OK");

    SSL_set_fd(ssl, new_sockfd);

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

        temp_buf = strstr(recv_buf, "GET /1/on HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_1, 1);
        }
        temp_buf = strstr(recv_buf, "GET /1/off HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_1, 0);
        }

        temp_buf = strstr(recv_buf, "GET /2/on HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_2, 1);
        }
        temp_buf = strstr(recv_buf, "GET /2/off HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_2, 0);
        }

        temp_buf = strstr(recv_buf, "GET /3/on HTTP/1.1");
        if (temp_buf) {;
            gpio_set_level(PIN_3, 1);
        }
        temp_buf = strstr(recv_buf, "GET /3/off HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_3, 0);
        }

        temp_buf = strstr(recv_buf, "GET /4/on HTTP/1.1");
        if (temp_buf) {
            gpio_set_level(PIN_4, 1);
        }
        temp_buf = strstr(recv_buf, "GET /4/off HTTP/1.1");
        if (temp_buf) {
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
        temp_buf = strstr(recv_buf, "GET /ip HTTP/1.1");
        if (temp_buf) {
            for (int i=0; i<16; i++) {
                if ((ip[i] >= '0' && ip[i] <= '9') || ip[i] == '.' || ip[i] == '_') {
                    send_data_1[ACK_1_OFFSET+i] = ip[i];
                } else {
                    send_data_1[ACK_1_OFFSET+i] = '_';
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
    vTaskDelay((150) / portTICK_PERIOD_MS);
    goto reconnect;
failed3:
    close(sockfd);
    sockfd = -1;
failed2:
    SSL_CTX_free(ctx);
    ctx = NULL;
failed1:
    vTaskDelete(NULL);
    ESP_LOGE(TAG, "task deleted");
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
        if (!ipify_created) {
            xTaskCreate(&ipify_task, "ipify_task", 8192, NULL, IPIFY_PRIORITY, NULL);
            ipify_created = true;
        }
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        if (!telegram_created) {
            xTaskCreate(&telegram_task, "telegram_task", 8192, NULL, TELEGRAM_PRIORITY, NULL);
            telegram_created = true;
        }
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
            .ssid     = WIFI_SSID,
            .password = WIFI_PASSW,
        },
    };
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_LOGI(TAG, "try start the WIFI SSID:[%s] password:[%s]\n", WIFI_SSID, WIFI_PASSW);

    while (! esp_wifi_start()) {
        vTaskDelay((3*1000) / portTICK_PERIOD_MS);
    }
    ESP_LOGI(TAG, "WIFI connected");
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
}
