/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include "sdkconfig.h"

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
#include "tls/openssl_server.h"
#include "ipify/ipify.h"
#include "telegram/telegram.h"


static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const static int CONNECTED_BIT = BIT0;


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
