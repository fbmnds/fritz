/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef _OPENSSL_SERVER_H_
#define _OPENSSL_SERVER_H_


#define TLS_TASK_NAME        "tls"
#define TLS_TASK_STACK_WORDS 10240
#define TLS_TASK_PRIORITY    5

#define TLS_RECV_BUF_LEN     1024

#define TLS_LOCAL_TCP_PORT   443

#define TLS_SERVER_ACK     "HTTP/1.1 200 OK\r\n" \
                           "Access-Control-Allow-Origin: "ORIGIN"\r\n" \
                           "Keep-Alive: timeout=2, max=10\r\n" \
                           "Connection: Keep-Alive\r\n" \
                         "Content-Type: text/plain\r\n" \
                         "Content-Length: 2\r\n\r\n" \
                         "{}" \
                         "\r\n"
#define TLS_SERVER_ACK_LEN strlen(TLS_SERVER_ACK)

#define TLS_SERVER_ACK_1 "HTTP/1.1 200 OK\r\n" \
                         "Access-Control-Allow-Origin: "ORIGIN"\r\n" \
                         "Keep-Alive: timeout=2, max=10\r\n" \
                         "Connection: Keep-Alive\r\n" \
                         "Content-Type: %s\r\n" \
                         "Content-Length: %d\r\n\r\n" \
                         "%s" \
                         "\r\n"
#define TLS_SERVER_ACK_1_LEN    81
#define TLS_SERVER_ACK_1_BUFLEN 8850
#define TLS_SERVER_ACK_1_STATE "{ \"fun_p64\": %d, \"zen\": %d, \"store\": %d, \"eth\": %d }"
#define TLS_SERVER_ACK_1_STATELEN 48

static bool connected = false;
static char ip[] = "___.___.___.___";


static bool ipify_created = false;
static bool telegram_created = false;

const static char *TAG = "relay";

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


static void tls_task(void *p)
{
    int ret;

    SSL_CTX *ctx;
    SSL *ssl;

    int sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    static char recv_buf[TLS_RECV_BUF_LEN];
    char *temp_buf;
    static char index_buf[TLS_SERVER_ACK_1_BUFLEN];
/*
    extern const unsigned char server_pem_start[] asm("_binary_server_pem_start");
    extern const unsigned char server_pem_end[]   asm("_binary_server_pem_end");
    const unsigned int server_pem_bytes = server_pem_end - server_pem_start;

    extern const unsigned char server_key_pem_start[] asm("_binary_server_key_pem_start");
    extern const unsigned char server_key_pem_end[]   asm("_binary_server_key_pem_end");
    const unsigned int server_key_pem_bytes = server_key_pem_end - server_key_pem_start;
*/
    set_api_key();

    // ESP_LOGI(TAG, "SSL server context create ......");
    /* For security reasons, it is best if you can use
       TLSv1_2_server_method() here instead of TLS_server_method().
       However some old browsers may not support TLS v1.2.
    */
    /*
    ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (!ctx) {
        ESP_LOGI(TAG, "failed");
        goto failed1;
    }
    ESP_LOGI(TAG, "OK");
    */
    /*
    ESP_LOGI(TAG, "SSL server context set own certification......");
    ret = SSL_CTX_use_certificate_ASN1(ctx, server_pem_bytes, server_pem_start);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");
    */
    /*
    ESP_LOGI(TAG, "SSL server context set private key......");
    ret = SSL_CTX_use_PrivateKey_ASN1(0, ctx, server_key_pem_start, server_key_pem_bytes);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed2;
    }
    ESP_LOGI(TAG, "OK");
    */
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
    /*
    ESP_LOGI(TAG, "SSL server create ......");
    ssl = SSL_new(ctx);
    if (!ssl) {
        ESP_LOGI(TAG, "failed");
        goto failed3;
    }
    ESP_LOGI(TAG, "OK");
    */
    connected = true;

    ESP_LOGI(TAG, "SSL server socket accept client ......");
    new_sockfd = accept(sockfd, (struct sockaddr *)&sock_addr, &addr_len);
    if (new_sockfd < 0) {
        ESP_LOGI(TAG, "failed" );
        goto failed4;
    }
    ESP_LOGI(TAG, "OK");

    //SSL_set_fd(ssl, new_sockfd);

    ret = SSL_accept(ssl);
    if (!ret) {
        ESP_LOGI(TAG, "failed");
        goto failed5;
    }
    ESP_LOGI(TAG, "OK");

    ESP_LOGI(TAG, "SSL server read message ......");

    memset(recv_buf, 0, TLS_RECV_BUF_LEN);
    ret = SSL_read(ssl, recv_buf, TLS_RECV_BUF_LEN - 1);

    ESP_LOGI(TAG, "SSL read: ret = %d\n%s", ret, recv_buf);

    temp_buf = strstr(recv_buf, API_KEY);
    if (!temp_buf) {
        ESP_LOGI(TAG, "SSL read: ignore request");
        ESP_LOGI(TAG, "%s", recv_buf);
        goto done;
    }
    temp_buf = NULL;

    temp_buf = strstr(recv_buf, "/1/on HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_1, 1);
        pin_state.fun_p64 = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/1/off HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_1, 0);
        pin_state.fun_p64 = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/2/on HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_2, 1);
        pin_state.store = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/2/off HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_2, 0);
        pin_state.store = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/3/on HTTP/1.1");
    if (temp_buf) {;
        gpio_set_level(PIN_3, 1);
        pin_state.zen = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/3/off HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_3, 0);
        pin_state.zen = 0;
        goto _200;
    }

    temp_buf = strstr(recv_buf, "/4/on HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_4, 1);
        pin_state.eth = 1;
        goto _200;
    }
    temp_buf = strstr(recv_buf, "/4/off HTTP/1.1");
    if (temp_buf) {
        gpio_set_level(PIN_4, 0);
        pin_state.eth = 0;
        goto _200;
    }

    goto index;

_200:
    ret = SSL_write(ssl, TLS_SERVER_ACK, TLS_SERVER_ACK_LEN);
    if (ret > 0) {
        ESP_LOGI(TAG, "OK");
    } else {
        ESP_LOGI(TAG, "error");
    }
    goto done;

index:
    /*
    temp_buf = strstr(recv_buf, "/index.html HTTP/1.1");
    if (temp_buf) {
        memset(index_buf, 0, TLS_SERVER_ACK_1_BUFLEN);
        sprintf(index_buf, TLS_SERVER_ACK_1,
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

    temp_buf = strstr(recv_buf, "/status HTTP/1.1");
    if (temp_buf) {
        memset(recv_buf, 0, TLS_RECV_BUF_LEN);
        sprintf(recv_buf, TLS_SERVER_ACK_1_STATE,
                          pin_state.fun_p64, pin_state.zen,
                          pin_state.store, pin_state.eth);
        memset(index_buf, 0, TLS_SERVER_ACK_1_BUFLEN);
        sprintf(index_buf, TLS_SERVER_ACK_1,
                           app_json,
                           TLS_SERVER_ACK_1_STATELEN,
                           recv_buf);
        ret = SSL_write(ssl, index_buf, strlen(index_buf));
        ESP_LOGI(TAG, "index_buf\n%s", index_buf);
        if (ret > 0) {
            ESP_LOGI(TAG, "OK");
        } else {
            ESP_LOGI(TAG, "error");
        }
    }
    // else drop request

done:
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


#endif
