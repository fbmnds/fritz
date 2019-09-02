/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include "esp32/sha.h"

#include "../secrets/secrets.h"

#define REGISTER_LEN      64
#define REGISTER_ITEM_LEN 14
#define REGISTER_ITEM_POS 0

#define HTTP_TASK_NAME        "http"
#define HTTP_TASK_STACK_WORDS 10240
#define HTTP_TASK_PRIORITY    5

#define HTTP_RECV_BUF_LEN     1024

#define HTTP_LOCAL_TCP_PORT   80

#define HTTP_SERVER_ACK \
"HTTP/1.1 200 OK\r\n" \
"Content-Type: text/plain\r\n" \
"Content-Length: 2\r\n\r\n" \
"{}" \
"\r\n"

#define HTTP_SERVER_ACK_LEN strlen(HTTP_SERVER_ACK)

#define HTTP_SERVER_ACK_500 \
"HTTP/1.1 500 OK\r\n" \
"Content-Type: text/plain\r\n" \
"Content-Length: 2\r\n\r\n" \
"{}" \
"\r\n"

#define HTTP_SERVER_ACK_LEN_500 strlen(HTTP_SERVER_ACK_500)


#define HTTP_SERVER_ACK_1 \
"HTTP/1.1 200 OK\r\n" \
"Content-Type: %s\r\n" \
"Content-Length: %d\r\n\r\n" \
"%s" \
"\r\n"

#define HTTP_SERVER_ACK_1_LEN    81
#define HTTP_SERVER_ACK_1_BUFLEN 8850
#define HTTP_SERVER_ACK_1_STATE "{ \"fun_p64\": %d, \"zen\": %d, \"store\": %d, \"eth\": %d }"
#define HTTP_SERVER_ACK_1_STATELEN 48

static bool connected = false;
static char ip[] = "___.___.___.___";
static bool renew_api_key = false;

const static char *TAG = HTTP_TASK_NAME;

#define PIN_1 GPIO_NUM_12
#define PIN_2 GPIO_NUM_14
#define PIN_3 GPIO_NUM_27
#define PIN_4 GPIO_NUM_26

static const char text_html[] = "text/html";
static const char app_json[]  = "text/plain";

typedef struct pin_state {
    int fun_p64;
    int zen;
    int store;
    int eth;
} pin_state_t;

pin_state_t pin_state = {
    .fun_p64 = 0,
    .zen     = 0,
    .store   = 0,
    .eth = 0,
};

int validate_req(char* rec_buf, const unsigned char* recv_buf_decr);

int register_req(uint32_t* req_register, int* register_idx, const unsigned char* item);

static void tls_task(void *p)
{
    int ret,sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    int in_len, idx;
    static          char recv_buf[HTTP_RECV_BUF_LEN];
    static unsigned char recv_buf2[HTTP_RECV_BUF_LEN];
    unsigned char* recv_buf_decr;
    char *temp_buf;
    static char index_buf[HTTP_SERVER_ACK_1_BUFLEN];

    static uint32_t req_register[REGISTER_LEN];
    int register_idx = -1;

    set_api_key();

    ESP_LOGI(TAG, "HTTP server create socket ......");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "HTTP server socket bind ......");
    memset(&sock_addr, 0, sizeof(sock_addr));
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = 0;
    sock_addr.sin_port = htons(HTTP_LOCAL_TCP_PORT);
    ret = bind(sockfd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "HTTP server socket listen ......");
    ret = listen(sockfd, 32);
    if (ret) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");

reconnect:
    connected = true;

    ESP_LOGI(TAG, "HTTP server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_len);
    if (new_sockfd < 0) {
        ESP_LOGI(TAG, "failed" );
        connected = false;
        goto failed4;
    }

    ESP_LOGI(TAG, "HTTP server read message ......");

    memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
    ret = read(new_sockfd, recv_buf, HTTP_RECV_BUF_LEN - 1);

    ESP_LOGI(TAG, "HTTP read: ret = %d\n%s", ret, recv_buf);

    //handle_request(recv_buf, temp_buf, API_KEY, ); 
    in_len = 0;
    idx = HTTP_RECV_BUF_LEN;
    while (--idx) {
        if (recv_buf[idx] == '\r' || recv_buf[idx] == '\n') recv_buf[idx] = '\0';
        if (recv_buf[idx] != '\0' && recv_buf[idx] != '\r' && recv_buf[idx] != '\n') break;
    }
    while (idx) {
        if ((recv_buf[idx] >= '0' && recv_buf[idx] <= '9') || 
            (recv_buf[idx] >= 'a' && recv_buf[idx] <= 'f')) {
            idx--; 
            in_len++;
        } else 
            break;
    }
    if (in_len) idx++;
    if (!idx) {
        ESP_LOGE(TAG, "HTTP read: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);        
        goto done;
    }

    ESP_LOGI(TAG, "recv_buf_decr %s", &recv_buf[idx]); 

    memset(recv_buf2, 0, HTTP_RECV_BUF_LEN);
    recv_buf_decr = recv_buf2;
    aes128_cbc_decrypt(&recv_buf[idx], in_len, recv_buf_decr);
    if (recv_buf_decr) {
        ESP_LOGI(TAG, "decrypted %s", recv_buf_decr); 
    }

    in_len = validate_req(recv_buf, recv_buf_decr);
    if (in_len < 0) {
        ESP_LOGE(TAG, "HTTP validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        goto _500;        
    }

    if (register_req(req_register, &register_idx, &recv_buf_decr[REGISTER_ITEM_POS])) {
        ESP_LOGE(TAG, "HTTP register error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        goto _500;        
    }

    temp_buf = strstr(recv_buf, API_KEY);
    if (!temp_buf) {
        ESP_LOGE(TAG, "HTTP API_KEY error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        goto done;
    }

    temp_buf = strstr(recv_buf, "/1/on");
    if (temp_buf) {
        gpio_set_level(PIN_1, 1);
        pin_state.fun_p64 = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/1/off");
    if (temp_buf) {
        gpio_set_level(PIN_1, 0);
        pin_state.fun_p64 = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/2/on");
    if (temp_buf) {
        gpio_set_level(PIN_2, 1);
        pin_state.store = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/2/off");
    if (temp_buf) {
        gpio_set_level(PIN_2, 0);
        pin_state.store = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/3/on");
    if (temp_buf) {;
        gpio_set_level(PIN_3, 1);
        pin_state.zen = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/3/off");
    if (temp_buf) {
        gpio_set_level(PIN_3, 0);
        pin_state.zen = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/4/on");
    if (temp_buf) {
        gpio_set_level(PIN_4, 1);
        pin_state.eth = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/4/off");
    if (temp_buf) {
        gpio_set_level(PIN_4, 0);
        pin_state.eth = 0;
        goto _200;
    }

    goto status;

_200:
    ret = write(new_sockfd, HTTP_SERVER_ACK, HTTP_SERVER_ACK_LEN);
    if (ret > 0) {
        ESP_LOGI(TAG, "HTTP 200 reply OK");
    } else {
        ESP_LOGE(TAG, "HTTP 200 reply error");
    }
    goto done;

_500:
    ret = write(new_sockfd, HTTP_SERVER_ACK_500, HTTP_SERVER_ACK_LEN_500);
    if (ret > 0) {
        ESP_LOGI(TAG, "HTTP 500 reply OK");
    } else {
        ESP_LOGE(TAG, "HTTP 500 reply error");
    }
    goto done;

/*
index:
    temp_buf = strstr(recv_buf, "/index.html");
    if (temp_buf) {
        memset(index_buf, 0, HTTP_SERVER_ACK_1_BUFLEN);
        sprintf(index_buf, HTTP_SERVER_ACK_1,
                           text_html,
                           main_html_index_html_len,
                           main_html_index_html);
        ret = SSL_write(ssl, index_buf, strlen(index_buf));
        ESP_LOGI(TAG, "index_buf\n%s", index_buf);
        if (ret > 0) {
            ESP_LOGI(TAG, "OK");
        } else {
            ESP_LOGI(TAG, "error");
        }
        goto done;
    }
    */

status:
    temp_buf = strstr(recv_buf, "/status");
    if (temp_buf) {
        memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
        sprintf(recv_buf, HTTP_SERVER_ACK_1_STATE,
                          pin_state.fun_p64, pin_state.zen,
                          pin_state.store, pin_state.eth);
        memset(index_buf, 0, HTTP_SERVER_ACK_1_BUFLEN);
        sprintf(index_buf, HTTP_SERVER_ACK_1,
                           app_json,
                           HTTP_SERVER_ACK_1_STATELEN,
                           recv_buf);
        ret = write(new_sockfd, index_buf, strlen(index_buf));
        ESP_LOGI(TAG, "index_buf\n%s", index_buf);
        if (ret > 0) {
            ESP_LOGI(TAG, "/status reply OK");
        } else {
            ESP_LOGE(TAG, "/status reply error");
        }
    }
    // else drop request

done:
    close(new_sockfd);
    new_sockfd = -1;
failed4:
    vTaskDelay((150) / portTICK_PERIOD_MS);
    goto reconnect;
failed3:
    close(sockfd);
    sockfd = -1;
failed2:
    vTaskDelete(NULL);
    ESP_LOGE(TAG, "task deleted");
    return ;
}

static void openssl_server_init(void)
{
    int ret;
    xTaskHandle openssl_handle;

    ret = xTaskCreate(tls_task,
                      HTTP_TASK_NAME,
                      HTTP_TASK_STACK_WORDS,
                      NULL,
                      HTTP_TASK_PRIORITY,
                      &openssl_handle);

    if (ret != pdPASS)  {
        ESP_LOGI(TAG, "create task %s failed", HTTP_TASK_NAME);
    }
}


int validate_req(char* recv_buf, const unsigned char* recv_buf_decr)
{
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;/x/on
    //     4    9    14   19   24   29
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;/x/off
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;/status
    int i = 0;

    while (recv_buf_decr[i]) {
        recv_buf[i] = (char) recv_buf_decr[i];
        i++;
    }
    recv_buf[i] = '\0';
    if (i < 30) return -1*i;
    if (recv_buf[4] != '-') return -4;
    if (recv_buf[9] != '-') return -9;
    if (recv_buf[19] != '-') return -19;
    if (recv_buf[24] != '-') return -24;
    if (recv_buf[14] != ';') return -14;
    if (recv_buf[29] != ';') return -29;
    return i;
}

int register_req(uint32_t *req_register, int *register_idx, const unsigned char* item)
{
    int pos;
    uint32_t hash;

    if (API_KEY_LEN != REGISTER_ITEM_LEN) {
        ESP_LOGE(TAG, "register_req system error: API_KEY_LEN != REGISTER_ITEM_LEN");
        return -1;
    }

    ESP_LOGI(TAG, "register_req item %s", item);
    esp_sha(SHA2_256, item, REGISTER_ITEM_LEN, (unsigned char *) &hash);
    ESP_LOGI(TAG, "register_req hash %ud", hash);

    // reject API_KEY as invalid register item
    pos = REGISTER_ITEM_LEN;
    for (int i=0; i<REGISTER_ITEM_LEN; i++) {
        if (item[i] == (unsigned char) API_KEY[i]) pos--;
    }
    if (pos == 0) return 1;

    for (pos=0; pos<=*register_idx; pos++) {
        if (req_register[pos] == hash) break;
    }        
    ESP_LOGI(TAG, "register_req pos %d", pos);

    // ignore replayed requests
    if (pos <= *register_idx) return 1;

    *register_idx += 1;
    ESP_LOGI(TAG, "register_req *register_idx %d", *register_idx);

    if (*register_idx == REGISTER_LEN) {
        ESP_LOGI(TAG, "register_req refresh exhausted register");
        for (pos=1; pos<REGISTER_LEN; pos++) req_register[pos] = 0;
        req_register[0] = hash;
        renew_api_key = true;
        return 0;
    } 

    ESP_LOGI(TAG, "register_req register new request");
    req_register[*register_idx] = hash;
    return 0;
}

#endif
