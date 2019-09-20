#ifndef _HTTP_UPLOAD_H_
#define _HTTP_UPLOAD_H_

#include <string.h>

#include "http_globals.h"



static const char upload_url[]  = "POST /upload/";
static const int  upload_url_len = 13;


static str_pt fn = {
    .str = NULL,
    .len = 0
};

int upload_fn (str_pt* fn, const char* recv_buf, const char* upload_url)
{
    char *ret;
    int idx;

    ret = strstr(recv_buf, upload_url);
    if (ret) {
        fn->str = ret+upload_url_len*sizeof(char);
        fn->len = 0;
        idx = upload_url_len;
        while (ret[idx] != '\0' &&
               ret[idx] != '\r' &&
               ret[idx] != '\n' &&
               ret[idx] != ' ') {
            idx++;
            fn->len++;
        }
        return 0;
    } else {
        fn = NULL;
        return 1;
    }
}


http_server_label_t post_upload(int new_sockfd, char* recv_buf, int ret)
{
	static unsigned char recv_buf2[HTTP_RECV_BUF_LEN];
	unsigned char* recv_buf_decr;
	char *temp_buf;
	int in_len, idx;

    static uint32_t req_register[REGISTER_LEN];
    int register_idx = -1;

    temp_buf = strstr(recv_buf, "GET");
    if (temp_buf) {
        ESP_LOGI(TAG, "GET upload: initial call");

        // TODO eliminate duplicated code
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
            return DONE;
        }

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
            return _500;        
        }        

        if (register_req(req_register, &register_idx, &recv_buf_decr[REGISTER_ITEM_POS])) {
            ESP_LOGE(TAG, "HTTP register error: ignore request");
            ESP_LOGE(TAG, "%s", recv_buf);
            return _500;        
        }        

        // TODO return 200, permitt-token
    }
    if (temp_buf) {
        ESP_LOGI(TAG, "POST upload sequence");
    }
    // else drop request
    return DONE;
}

#endif