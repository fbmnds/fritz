#ifndef _HTTP_UPLOAD_H_
#define _HTTP_UPLOAD_H_

#include <string.h>
#include <stdio.h>



#include "http_globals.h"

static FILE* upload_file = NULL;

static char UPLOAD_KEY[] = "____-____-____";
static char UPLOAD_IV[]  = "____-____-____";

#define SD_PREFIX_LEN 7
static char SD_PREFIX[] = "/sdcard";

// #define UPLOAD_BUF_STR_LEN 256
// static char upload_buf_str[UPLOAD_BUF_STR_LEN];
// static str_pt upload_buf = {
//     .str = upload_buf_str,
//     .len = UPLOAD_BUF_STR_LEN
// };


// http_server_label_t post_upload2(char* req_register, int* register_idx, 
// 	                            int new_sockfd, char* recv_buf)
// {
// 	static unsigned char recv_buf2[HTTP_RECV_BUF_LEN];
// 	unsigned char* recv_buf_decr;
// 	str_pt recv_p;

// 	char *temp_buf;
// 	int in_len, idx;

//     temp_buf = strstr(recv_buf, "GET");
//     if (temp_buf) {
//         ESP_LOGI(TAG, "GET upload: initial call");

//         // TODO eliminate duplicated code
//         in_len = 0;
//         idx = HTTP_RECV_BUF_LEN;
//         while (--idx) {
//             if (recv_buf[idx] == '\r' || recv_buf[idx] == '\n') recv_buf[idx] = '\0';
//             if (recv_buf[idx] != '\0' && recv_buf[idx] != '\r' && recv_buf[idx] != '\n') break;
//         }
//         while (idx) {
//             if ((recv_buf[idx] >= '0' && recv_buf[idx] <= '9') || 
//                 (recv_buf[idx] >= 'a' && recv_buf[idx] <= 'f')) {
//                 idx--; 
//                 in_len++;
//             } else 
//                 break;
//         }
//         if (in_len) idx++;
//         if (!idx) {
//             ESP_LOGE(TAG, "HTTP read: ignore request");
//             ESP_LOGE(TAG, "%s", recv_buf);        
//             return DONE;
//         }

//         memset(recv_buf2, 0, HTTP_RECV_BUF_LEN);
//         recv_buf_decr = recv_buf2;
//         aes128_cbc_decrypt(&recv_buf[idx], in_len, recv_buf_decr);
//         if (recv_buf_decr) {
//             ESP_LOGI(TAG, "decrypted %s", recv_buf_decr); 
//         }

//         in_len = validate_req(recv_buf, recv_buf_decr);
//         if (in_len < 0) {
//             ESP_LOGE(TAG, "HTTP validation error: ignore request");
//             ESP_LOGE(TAG, "%s", recv_buf);
//             return _500;        
//         }        


//         for (int i=0; i<REGISTER_ITEM_LEN; i++) recv_p.str[i] = (char) recv_buf_decr[REGISTER_ITEM_POS + i];
//         if (register_req(req_register, register_idx, &recv_p)) {
//             ESP_LOGE(TAG, "HTTP register error: ignore request");
//             ESP_LOGE(TAG, "%s", recv_buf);
//             return _500;        
//         }        

//         // TODO return 200, permitt-token
//     }
//     if (temp_buf) {
//         ESP_LOGI(TAG, "POST upload sequence");
//     }
//     // else drop request
//     return DONE;
// }


http_server_label_t post_upload(int new_sockfd, char* recv_buf, int ret)
{
	str_pt recv_p;
	char iv[API_KEY_LEN];
	//char *temp_buf;
	int idx, prefix_len;

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
    idx = rt_post_upload.len;
	recv_p.str = &recv_buf[idx];
	recv_p.len = 0;
    while ((recv_buf[idx] >= '0' && recv_buf[idx] <= '9') || 
            (recv_buf[idx] >= 'a' && recv_buf[idx] <= 'f')) {
    	idx++;
        recv_p.len++;
    } 

    ESP_LOGI(TAG, "file for writing, encrypted: %s", recv_p.str);

    if (aes128_cbc_decrypt3(&recv_p, &recv_p)) return _500;

    ESP_LOGI(TAG, "file for writing, decrypted: %s", recv_p.str);

    memset(&recv_buf[HTTP_RECV_BUF_SHORT_LEN], 0, HTTP_RECV_BUF_SHORT_LEN);
    prefix_len = strlen(SD_PREFIX);

    for (int i=0; i<prefix_len; i++) 
    	recv_buf[HTTP_RECV_BUF_SHORT_LEN+i] = SD_PREFIX[i];
    if (recv_p.str[0] != '/') {
    	recv_buf[HTTP_RECV_BUF_SHORT_LEN+prefix_len] = '/'; 
    	for (int i=0; i<recv_p.len; i++) recv_buf[HTTP_RECV_BUF_SHORT_LEN+prefix_len+i+1] = recv_p.str[i];
    } else
		for (int i=0; i<recv_p.len; i++) recv_buf[HTTP_RECV_BUF_SHORT_LEN+prefix_len+i] = recv_p.str[i];
    
    recv_p.str = &recv_buf[HTTP_RECV_BUF_SHORT_LEN];
    recv_p.len = recv_p.len + AES_KEY_SIZE - recv_p.len%AES_KEY_SIZE;

    // open fn
	ESP_LOGI(TAG, "file for writing, prefixed: %s", recv_p.str);

    FILE* f = fopen(recv_p.str, "w");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for writing");
        return _500;
    }
    
    // generate IV
    if (strlen(UPLOAD_IV) != API_KEY_LEN) {
        ESP_LOGE(TAG, "UPLOAD_IV configuration error");
        return _500;   	
    }
    set_iv(UPLOAD_IV);

    // build encrypted response
    memset(&recv_buf[0], 0, HTTP_RECV_BUF_SHORT_LEN);
    for (int i=0; i<API_KEY_LEN; i++) recv_buf[i] = UPLOAD_IV[i];
    recv_buf[API_KEY_LEN] = ';';
	for (int i=API_KEY_LEN+1; i<2*API_KEY_LEN+1; i++) recv_buf[i] = UPLOAD_KEY[i-API_KEY_LEN-1];
	ESP_LOGI(TAG, "response '%s'", recv_buf);

	idx = 2*API_KEY_LEN+1;
	idx = idx + AES_KEY_SIZE - idx%AES_KEY_SIZE;
	aes128_cbc_encrypt(recv_buf, idx, recv_buf, &idx);
	ESP_LOGI(TAG, "response encrypted '%s'", recv_buf);

	if (strlen(recv_buf) != idx) {
        ESP_LOGE(TAG, "response encryption error");
        return _500;   		
	}

    // 200, response
	memset(recv_p.str,0, recv_p.len);
	sprintf(recv_p.str, HTTP_SERVER_ACK_1, app_json, idx, recv_buf);

    idx = write(new_sockfd, recv_p.str, strlen(recv_p.str));
    ESP_LOGI(TAG, "response 200 OK\n%s", recv_p.str);
    if (idx > 0) {
        ESP_LOGI(TAG, "/upload reply sent, OK");
    	return DONE;    
    } else {
        ESP_LOGE(TAG, "/upload reply sent, error");
        close(upload_file);
        return _500;
    }

    // else drop request
    
}

#endif