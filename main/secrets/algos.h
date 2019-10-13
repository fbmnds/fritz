#ifndef _ALGOS_H_
#define _ALGOS_H_

#define AES_KEY_SIZE        16

#ifndef TEST
#include "secrets.h"
#endif

#define AES_B64_BUF_LEN   8*1024
//#define AES_B64_BUF_LEN_2 2048

#define API_KEY_LEN 14
#define API_KEY_LEN_m2 12

static char API_KEY[]      = "____-____-____";
static char API_KEY_PREV[] = "____-____-____";

static char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static int cs_len = 36;

static void set_api_key() {
    for (int i=0; i<API_KEY_LEN; i++) API_KEY_PREV[i] = API_KEY[i];  // TODO critical section
    char buf[API_KEY_LEN_m2];
    esp_fill_random(buf, API_KEY_LEN_m2);
    for (int i=0; i<4; i++)  API_KEY[i]   = cs[buf[i]%cs_len];
    for (int i=4; i<8; i++)  API_KEY[i+1] = cs[buf[i]%cs_len];
    for (int i=8; i<12; i++) API_KEY[i+2] = cs[buf[i]%cs_len];
    ESP_LOGI("secret", "API_KEY %s", API_KEY);
}

typedef struct str_p {
    char* str;
    int  len;
} str_pt;

typedef struct u_str_p {
    unsigned char* u_str;
    int  len;
} u_str_pt;

static void set_nonce(char* s) {
    char buf[API_KEY_LEN_m2];
    esp_fill_random(buf, API_KEY_LEN_m2);
    for (int i=0; i<4; i++)  s[i]   = cs[buf[i]%cs_len];
    for (int i=4; i<8; i++)  s[i+1] = cs[buf[i]%cs_len];
    for (int i=8; i<12; i++) s[i+2] = cs[buf[i]%cs_len];
    ESP_LOGI("secret", "IV %s", s);
}

static void set_iv(unsigned char* p, size_t aes_key_size)
{
    esp_fill_random(p, aes_key_size);
}

static unsigned char aes_hex_in[AES_B64_BUF_LEN];
static unsigned char aes_hex_out[AES_B64_BUF_LEN];

void aes128_cbc_encrypt(const char*      in,   
                        int              in_len, 
                        char*            out2, 
                        int*             out2_len,
                        esp_aes_context* secret_ctx,
                        unsigned char*   iv)
{
	int ret, mod_key_size;
	size_t in_len2;
    unsigned char secret_iv[AES_KEY_SIZE];

	mod_key_size = in_len % AES_KEY_SIZE;
	if (mod_key_size) 
		in_len2 = (size_t) (in_len + AES_KEY_SIZE - mod_key_size);
	else
		in_len2 = (size_t) in_len;
	ESP_LOGI("secret", "aes128_cbc_encrypt i n_len2 = %d\n%s\n", in_len2, in);

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

	bzero(aes_hex_in, sizeof(aes_hex_in));
	for (int i=0; i<in_len; i++)       aes_hex_in[i] = (unsigned char) in[i];
	for (int i=in_len; i<in_len2; i++) aes_hex_in[i] = (unsigned char) ' ';

    bzero(aes_hex_out, sizeof(aes_hex_out));
	memset(out2, 0, *out2_len);

	ret = esp_aes_crypt_cbc(secret_ctx,        // AES context
                            ESP_AES_ENCRYPT,   // AES_ENCRYPT or AES_DECRYPT
                            in_len2,           // length of the input data
                            secret_iv,         // initialization vector (updated after use)       
                            aes_hex_in,        // buffer holding the input data
                            aes_hex_out);      // buffer holding the output data
//  return 0 if successful, or ERR_AES_INVALID_INPUT_LENGTH       
    if (ret) {
    	ESP_LOGE("secret", "esp_aes_crypt_cbc aes_hex_out failed, ret = %d", ret); 
    	out2 = NULL;
    	*out2_len = 0;
    	return;

    }
	for (size_t i=0; i<in_len2; i++) {
		sprintf(out2+i*2, "%02x", aes_hex_out[i]);
	} 
    *out2_len = 2*in_len2+1;
}

uint8_t ctoi (char c)
{
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t) (10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (uint8_t) (10 + c - 'a');
    return -1;
}


int aes128_cbc_decrypt3(str_pt*          in, 
                        str_pt*          out,
                        esp_aes_context* secret_ctx,
                        unsigned char*   iv)
{
    int ret;
    uint8_t *aes_hex_in_8;
    unsigned char secret_iv[AES_KEY_SIZE];

    assert(in->len <= out->len);

    if (in->len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "esp_aes_crypt_cbc aes_hex_in failed, in_len = %d", in->len);
        return -1;
    }

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

    aes_hex_in_8 = (uint8_t *) aes_hex_in;
    bzero(aes_hex_in, sizeof(aes_hex_in));
    for (int i=0; i<in->len/2; i++) {
        aes_hex_in_8[i] = ctoi(in->str[2*i])*16 + ctoi(in->str[2*i+1]);
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in_8[i]);
    }

    
    //AES_set_decrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &dec_key); // Size of key is in bits
    //AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &dec_key, iv, AES_DECRYPT);

    //AES_set_decrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &dec_key); // Size of key is in bits
    //AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &dec_key, iv, AES_DECRYPT);

    ret = esp_aes_crypt_cbc(secret_ctx,       // AES context
                            ESP_AES_DECRYPT,   // AES_ENCRYPT or AES_DECRYPT
                            in->len/2,         // length of the input data
                            secret_iv,         // initialization vector (updated after use)       
                            aes_hex_in,        // buffer holding the input data
                            aes_hex_out);      // buffer holding the output data
//  return 0 if successful, or ERR_AES_INVALID_INPUT_LENGTH       
    if (ret) {
        ESP_LOGE("secret", "esp_aes_crypt_cbc aes_hex_in failed, ret = %d", ret); 
        return -1;
    }

    bzero(out->str, in->len);
    /* copy with terminating '\0' */
    for (int i=0; i<=in->len/2; i++) out->str[i] = (char) aes_hex_out[i];
    out->len = strlen(out->str); 

    return 0;    
}


int aes128_cbc_decrypt4(str_pt*          in, 
                        u_str_pt*        out,
                        esp_aes_context* secret_ctx,
                        unsigned char*   secret_iv)
{
    int ret;
    uint8_t *aes_hex_in_8;
    //AES_KEY dec_key;
    //unsigned char iv[AES_KEY_SIZE];

    assert(in->len <= out->len);

    if (in->len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "esp_aes_crypt_cbc aes_hex_in failed, in_len = %d", in->len);
        return -1;
    }

    //for (int i = 0; i < AES_KEY_SIZE; i++) iv[i] = IV[i];

    aes_hex_in_8 = (uint8_t *) aes_hex_in;
    bzero(aes_hex_in, sizeof(aes_hex_in));
    for (int i=0; i<in->len/2; i++) {
        aes_hex_in_8[i] = ctoi(in->str[2*i])*16 + ctoi(in->str[2*i+1]);
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in_8[i]);
    }
    
    ret = esp_aes_crypt_cbc(secret_ctx,       // AES context
                            ESP_AES_DECRYPT,   // AES_ENCRYPT or AES_DECRYPT
                            in->len/2,         // length of the input data
                            secret_iv,         // initialization vector (updated after use)       
                            aes_hex_in,        // buffer holding the input data
                            aes_hex_out);      // buffer holding the output data
//  return 0 if successful, or ERR_AES_INVALID_INPUT_LENGTH       
    if (ret) {
        ESP_LOGE("secret", "esp_aes_crypt_cbc aes_hex_in failed, ret = %d", ret); 
        return -1;
    }

    out->len = in->len/2;
    bzero(out->u_str, out->len);
    for (int i=0; i<out->len; i++) out->u_str[i] = aes_hex_out[i];

    return 0;    
}


#endif