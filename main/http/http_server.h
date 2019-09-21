
#ifndef _HTTP_SERVER_H_
#define _HTTP_SERVER_H_

#include "esp32/sha.h"

#include "../secrets/secrets.h"

#include "http_globals.h"
#include "http_upload.h"



static void tls_task(void *p)
{
    int ret,sockfd, new_sockfd;
    socklen_t addr_len;
    struct sockaddr_in sock_addr;

    int idx;
    static char recv_buf[HTTP_RECV_BUF_LEN];
    str_pt recv_p;
    char *temp_buf;
    static char recv_buf_short[HTTP_RECV_BUF_SHORT_LEN];
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

    if (ret < HTTP_RECV_MIN_LEN) goto done;

    fn.str = (char *) rt_post_upload;
    fn.len = strlen(rt_post_upload);
    if (cmp_str_head(recv_buf, &fn)) {
        switch (post_upload(new_sockfd, recv_buf, ret)) {
            case _200: goto _200;
            case _500: goto _500;
            default:   goto done;
        }
    }

    recv_p.str = NULL;
    recv_p.len = 0; 
    switch (set_payload_idx2 (&recv_p, recv_buf)) {
        case DONE: goto done;
        default:   break;
    }

    //ESP_LOGI(TAG, "recv_buf decrypted %s", *(recv_p.str)); // recv_p IS null terminated, as recv_buf is

    aes128_cbc_decrypt3(&recv_p, &recv_p); // recv_p IS null terminated, being half as long as the encrypted string
    /*
    if (recv_p.str) {
        ESP_LOGI(TAG, "decrypted %s", *(recv_p.str)); 
    }
    */

    if (validate_req_base(&recv_p) < 0) {
        ESP_LOGE(TAG, "HTTP validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        goto _500;        
    }

    if (register_req(req_register, &register_idx, recv_p.str)) {
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
        memset(recv_buf_short, 0, HTTP_RECV_BUF_SHORT_LEN);
        sprintf(recv_buf_short, HTTP_SERVER_ACK_1_STATE,
                                pin_state.fun_p64, pin_state.zen,
                                pin_state.store, pin_state.eth);
        memset(index_buf, 0, HTTP_SERVER_ACK_1_BUFLEN);
        sprintf(index_buf, HTTP_SERVER_ACK_1,
                           app_json,
                           HTTP_SERVER_ACK_1_STATELEN,
                           recv_buf_short);
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



#endif
