#ifndef _HTTP_UPLOAD_H_
#define _HTTP_UPLOAD_H_

#include <string.h>
#include <stdio.h>


#include "http_globals.h"

static FILE* upload_file = NULL;

static char UPLOAD_KEY[] = "____-____-____";
static char UPLOAD_IV[]  = "____-____-____";

#define UPLOAD_BUF_STR_LEN 256
static char upload_buf_str[UPLOAD_BUF_STR_LEN];
static str_pt upload_buf = {
    .str = upload_buf_str,
    .len = UPLOAD_BUF_STR_LEN
};


int get_upload_fn (str_pt* fn, const char* recv_buf)
{
    char *ret;
    int idx;

    return 0;
/*
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
*/
}

http_server_label_t post_upload2(char* req_register, int* register_idx, 
	                            int new_sockfd, char* recv_buf)
{
	static unsigned char recv_buf2[HTTP_RECV_BUF_LEN];
	unsigned char* recv_buf_decr;
	str_pt recv_p;

	char *temp_buf;
	int in_len, idx;

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


        for (int i=0; i<REGISTER_ITEM_LEN; i++) recv_p.str[i] = (char) recv_buf_decr[REGISTER_ITEM_POS + i];
        if (register_req(req_register, register_idx, &recv_p)) {
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


http_server_label_t post_upload(int new_sockfd, char* recv_buf, int ret)
{
	str_pt recv_p;

	char *temp_buf;
	int idx;

    if (upload_file) return _500;

    // validate API_KEY
    recv_p.str = NULL;
    recv_p.len = 0; 
    switch (set_payload_idx2 (&recv_p, recv_buf)) {
        case DONE: return DONE;
        default:   break;
    }

    ESP_LOGI(TAG, "recv_buf encrypted %s", recv_p.str); // recv_p IS null terminated, as recv_buf is

    aes128_cbc_decrypt3(&recv_p, &recv_p); // recv_p IS null terminated, being half as long as the encrypted string
    
    if (recv_p.str) {
        ESP_LOGI(TAG, "decrypted %s", recv_p.str); 
    }
    
    if (validate_req_base(&recv_p) < 0) {
        ESP_LOGE(TAG, "HTTP validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        return _500;        
    }

    // set UPLOAD_KEY
    for (int i=0; i<API_KEY_LEN; i++) UPLOAD_KEY[i] = recv_p.str[i];

    // get_upload_fn

    // open fn

    // generate IV

    // 200, response

    // else drop request
    return DONE;
}

#endif