#ifndef _HTTP_UPLOAD_H_
#define _HTTP_UPLOAD_H_

#include <string.h>
#include <stdio.h>



#include "http_globals.h"
#include "../secrets/base64.h"

static FILE* upload_file = NULL;
static int upload_file_len = 0;

static char UPLOAD_KEY[] = "____-____-____";
static char UPLOAD_NONCE[]  = "____-____-____";

static esp_aes_context secret_upload_ctx = {
    .key_bytes = AES_KEY_SIZE,
    .key = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}
};
static unsigned char* UPLOAD_IV = secret_upload_ctx.key;

#define ACCESS_TOKEN_ENCRYPT_LEN 2*(2*API_KEY_LEN+1)

#define SD_PREFIX_LEN 7
static char SD_PREFIX[] = "/sdcard";



http_server_label_t post_upload(int new_sockfd, char* recv_buf, int recv_buf_received_len)
{
	str_pt recv_p, api_key;
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

    aes128_cbc_decrypt3(&recv_p, &recv_p, &secret_ctx, IV); // recv_p IS null terminated, being half as long as the encrypted string
    
    if (recv_p.str) {
        ESP_LOGI(TAG, "decrypted %s", recv_p.str); 
    }
   
    api_key.str = API_KEY;
    api_key.len = API_KEY_LEN;
    if (validate_req_base(&recv_p, &api_key) < 0) {
        ESP_LOGE(TAG, "HTTP validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        return _500;        
    }

    idx = 2*API_KEY_LEN+2;
    if (recv_p.len < idx) {
        ESP_LOGE(TAG, "HTTP upload file length validation error: ignore request");
        return _500;      	
    }
    
    upload_file_len = 0;
    while (recv_p.str[idx] >= '0' && recv_p.str[idx] <= '9') {
    	if (idx == 2*API_KEY_LEN+2) 
    		upload_file_len = recv_p.str[idx] - '0';
    	else 
    		upload_file_len = 10*upload_file_len + recv_p.str[idx] - '0'; 
    	idx++;
    }
    if (upload_file_len < 1) {
        ESP_LOGE(TAG, "HTTP upload file length validation error: ignore request");
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

    if (aes128_cbc_decrypt3(&recv_p, &recv_p, &secret_ctx, IV)) return _500;

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
    upload_file = f;
    
    // generate IV
    if (strlen(UPLOAD_NONCE) != API_KEY_LEN) {
        ESP_LOGE(TAG, "UPLOAD_NONCE configuration error");
        return _500;   	
    }
    set_nonce(UPLOAD_NONCE);

    // build encrypted response
    memset(&recv_buf[0], 0, HTTP_RECV_BUF_SHORT_LEN);
    for (int i=0; i<API_KEY_LEN; i++) recv_buf[i] = UPLOAD_NONCE[i];
    recv_buf[API_KEY_LEN] = ';';
	for (int i=API_KEY_LEN+1; i<2*API_KEY_LEN+1; i++) recv_buf[i] = UPLOAD_KEY[i-API_KEY_LEN-1];
	recv_buf[2*API_KEY_LEN+1] = ';';
	set_iv(UPLOAD_IV, AES_KEY_SIZE);
	for (int i=0; i<AES_KEY_SIZE; i++) 
		sprintf(recv_buf+2*API_KEY_LEN+2+i*2, "%02x", UPLOAD_IV[i]); 
	ESP_LOGI(TAG, "response '%s'", recv_buf);

	idx = 2*API_KEY_LEN+1;
	idx = idx + AES_KEY_SIZE - idx%AES_KEY_SIZE;
	aes128_cbc_encrypt(recv_buf, idx, recv_buf, &idx, &secret_ctx, IV);
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
        ESP_LOGI(TAG, "/upload reply transmission OK");
    	return DONE;    
    } else {
        ESP_LOGE(TAG, "/upload reply transmission failed");
        fclose(upload_file);
        return _500;
    }
}

http_server_label_t post_put(int new_sockfd, char* recv_buf, int recv_buf_received_len)
{
	str_pt recv_p, upload_chk;
	int idx, prefix_len;

    if (!upload_file) return _500;

    // validate UPLOAD_KEY
    recv_p.str = strstr(recv_buf, "Access_Token: ");
    if (!recv_p.str) return _500;

    recv_p.str += strlen("Access_Token: ")*sizeof(char);
    recv_p.len = ACCESS_TOKEN_ENCRYPT_LEN;
    recv_p.str[ACCESS_TOKEN_ENCRYPT_LEN] = '\0';
    ESP_LOGI(TAG, "recv_buf encrypted %s", recv_p.str); 

    aes128_cbc_decrypt3(&recv_p, &recv_p, // recv_p IS null terminated, being half as long as the encrypted string
                        &secret_ctx, UPLOAD_IV); 
    
    if (recv_p.str) {
        ESP_LOGI(TAG, "decrypted %s", recv_p.str); 
    }
    
    upload_chk.str = UPLOAD_KEY;
    upload_chk.len = API_KEY_LEN; // checked in post_upload
    if (validate_req_base(&recv_p, &upload_chk) < 0) {
        ESP_LOGE(TAG, "HTTP validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        return _500;        
    }

    // check UPLOAD_NONCE
    upload_chk.str = UPLOAD_NONCE;
    //upload_chk.len = API_KEY_LEN;
    if(!cmp_str_head(recv_p.str, &upload_chk)) {
        ESP_LOGE(TAG, "HTTP upload nonce validation error: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);
        return _500;    	
    }

    // get payload position
    recv_p.str = NULL;
    recv_p.len = 0;
    switch (set_payload_idx2 (&recv_p, recv_buf)) {
        case DONE: return _500;
        default:   break;
    }

    // base64 decode payload
    aes128_cbc_decrypt4(&recv_p, (u_str_pt *)&recv_p, &secret_upload_ctx, UPLOAD_IV);

    // write to file
    recv_p.str[recv_p.len] = '\0';
    fputs(recv_p.str, upload_file);
    
    // close on end-of-transaction
    assert(sizeof(char) == sizeof(unsigned char));
    assert(sizeof(char) == 1);
    upload_file_len -= recv_p.len;

    if (upload_file_len == 0) {
    	fclose(upload_file);
    	upload_file = NULL;
    	return _200;
    }

    // generate IV
    if (strlen(UPLOAD_NONCE) != API_KEY_LEN) {
        ESP_LOGE(TAG, "UPLOAD_NONCE configuration error");
        return _500;   	
    }
    set_nonce(UPLOAD_NONCE);

    // build encrypted response
    memset(&recv_buf[0], 0, HTTP_RECV_BUF_SHORT_LEN);
    for (int i=0; i<API_KEY_LEN; i++) recv_buf[i] = UPLOAD_NONCE[i];
    recv_buf[API_KEY_LEN] = ';';
	for (int i=API_KEY_LEN+1; i<2*API_KEY_LEN+1; i++) recv_buf[i] = UPLOAD_KEY[i-API_KEY_LEN-1];
	ESP_LOGI(TAG, "response '%s'", recv_buf);

	idx = 2*API_KEY_LEN+1;
	idx = idx + AES_KEY_SIZE - idx%AES_KEY_SIZE;
	aes128_cbc_encrypt(recv_buf, idx, recv_buf, &idx, &secret_ctx, IV);
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
        ESP_LOGI(TAG, "/upload reply transmission OK");
    	return DONE;    
    } else {
        ESP_LOGE(TAG, "/upload reply transmission failed");
        fclose(upload_file);
        return _500;
    }
}
#endif