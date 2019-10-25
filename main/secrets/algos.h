#ifndef _ALGOS_H_
#define _ALGOS_H_

#define AES_KEY_SIZE        16

#ifdef TEST
#include "../../test/test_secrets.h"
#else
#include "secrets.h"
#endif

#ifdef GCC_X86

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/aes.h>

#define AES_ENCRYPT     1
#define AES_DECRYPT     0

static void esp_fill_random(char *s, int len)
{
    time_t t;
    srand((unsigned) time(&t));
    for (int i=0; i < len; i++) s[i] = (unsigned char) rand();
}

#define close(f) fclose(f)
#define write(x,y,z) 1

#endif /* GCC_X86 */


#define AES_B64_BUF_LEN   8*1024
//#define AES_B64_BUF_LEN_2 2048

#define API_KEY_LEN 14
#define API_KEY_LEN_m2 12

static char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static int cs_len = 36;

static void set_api_key() 
{
    unsigned char buf[API_KEY_LEN_m2];

    for (int i=0; i<API_KEY_LEN; i++) API_KEY_PREV[i] = API_KEY[i];  // TODO critical section

#ifdef GCC_X86
    esp_fill_random(buf, (int)API_KEY_LEN_m2);
#else
    esp_fill_random(buf, (size_t) API_KEY_LEN_m2);
#endif

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

static void set_nonce(char* s) 
{
    unsigned char buf[API_KEY_LEN_m2];
#ifdef GCC_X86
    esp_fill_random(buf, (int)API_KEY_LEN_m2);
#else
    esp_fill_random(buf, (size_t) API_KEY_LEN_m2);
#endif
    for (int i=0; i<4; i++)  s[i]   = cs[buf[i]%cs_len];
    for (int i=4; i<8; i++)  s[i+1] = cs[buf[i]%cs_len];
    for (int i=8; i<12; i++) s[i+2] = cs[buf[i]%cs_len];
    printf("set_nonce '"); for (int i=0; i<API_KEY_LEN; i++) printf("%c", s[i]); printf("'\n");
    ESP_LOGI("secret", " set_nonce '%s'", s);
}

#ifdef GCC_X86
static void set_iv(unsigned char* p, int aes_key_size)
{
    esp_fill_random(p, aes_key_size);
}
#else
static void set_iv(unsigned char* p, size_t aes_key_size)
{
    esp_fill_random(p, aes_key_size);
}
#endif

static unsigned char aes_hex_in[AES_B64_BUF_LEN];
static unsigned char aes_hex_out[AES_B64_BUF_LEN];

void aes128_cbc_encrypt(const char*      in,   
                        int              in_len, 
                        char*            out2, 
                        int*             out2_len,
                        const esp_aes_context* secret_ctx,
                        const unsigned char*   iv)
{
	int ret;
#ifdef GCC_X86
    AES_KEY enc_key;
#endif
    unsigned char secret_iv[AES_KEY_SIZE];

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

    assert(in_len % AES_KEY_SIZE == 0);

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

	bzero(aes_hex_in, sizeof(aes_hex_in));
	for (int i=0; i<in_len; i++) aes_hex_in[i] = (unsigned char) in[i];
	//for (int i=in_len; i<in_len; i++) aes_hex_in[i] = (unsigned char) ' ';

    bzero(aes_hex_out, sizeof(aes_hex_out));
	memset(out2, 0, *out2_len);

#ifdef GCC_X86
    AES_set_encrypt_key(secret_ctx->key, sizeof(secret_ctx->key)*8, &enc_key);
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &enc_key, secret_iv, AES_ENCRYPT);
#else
	ret = esp_aes_crypt_cbc((esp_aes_context*) secret_ctx,        // AES context
                            ESP_AES_ENCRYPT,   // AES_ENCRYPT or AES_DECRYPT
                            (size_t) in_len,   // length of the input data
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
#endif /* GCC_X86 */
	for (size_t i=0; i<in_len; i++) {
		sprintf(out2+i*2, "%02x", aes_hex_out[i]);
	} 
    *out2_len = 2*in_len;
}

int8_t ctoi (char c)
{
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t) (10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (uint8_t) (10 + c - 'a');
    return -1;
}


int aes128_cbc_decrypt3(str_pt* in, 
                        str_pt* out,
                        const esp_aes_context* secret_ctx,
                        const unsigned char*   iv)
{
    int ret;
#ifdef GCC_X86
    AES_KEY dec_key;
#endif    
    unsigned char secret_iv[AES_KEY_SIZE];

    assert(in->len <= out->len);
    if (in->len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "aes128_cbc_decrypt3 aes_hex_in failed, in_len = %d", in->len);
        return -1;
    }

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

    memset(aes_hex_in, 0, AES_B64_BUF_LEN);
    for (int i=0; i<in->len/2; i++) {
        ret = ctoi(in->str[2*i]);
        if (ret < 0) return -1;
        aes_hex_in[i] = ret*16;
        ret = ctoi(in->str[2*i+1]);
        if (ret < 0) return -1;
        aes_hex_in[i] += ret;
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in[i]);
    }

    memset(aes_hex_out, 0, AES_B64_BUF_LEN);
#ifdef GCC_X86
    AES_set_decrypt_key(secret_ctx->key, sizeof(secret_ctx->key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, in->len/2, &dec_key, secret_iv, AES_DECRYPT);
#else 
    ret = esp_aes_crypt_cbc((esp_aes_context*) secret_ctx,       // AES context
                            ESP_AES_DECRYPT,  // AES_ENCRYPT or AES_DECRYPT
                            in->len/2,        // length of the input data
                            secret_iv,        // initialization vector (updated after use)       
                            aes_hex_in,       // buffer holding the input data
                            aes_hex_out);     // buffer holding the output data
//  return 0 if successful, or ERR_AES_INVALID_INPUT_LENGTH       
    if (ret) {
        ESP_LOGE("secret", "esp_aes_crypt_cbc aes_hex_in failed, ret = %d", ret); 
        return -1;
    }
#endif /* GCC_X86 */

    bzero(out->str, in->len);
    for (int i=0; i<in->len/2; i++) out->str[i] = (char) aes_hex_out[i];
    out->len = in->len/2; 

    return 0;    
}


int aes128_cbc_decrypt4(str_pt*   in, 
                        u_str_pt* out,
                        const esp_aes_context* secret_ctx,
                        const unsigned char*   iv)
{
    int ret;
#ifdef GCC_X86
    AES_KEY dec_key;
#endif    
    unsigned char secret_iv[AES_KEY_SIZE];

    assert(in->len <= out->len);
    if (in->len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "aes128_cbc_decrypt3 aes_hex_in failed, in_len = %d", in->len);
        return -1;
    }

    for (int i = 0; i < AES_KEY_SIZE; i++) secret_iv[i] = iv[i];

    memset(aes_hex_in, 0, AES_B64_BUF_LEN);
    for (int i=0; i<in->len/2; i++) {
        ret = ctoi(in->str[2*i]);
        if (ret < 0) return -1;
        aes_hex_in[i] = ret*16;
        ret = ctoi(in->str[2*i+1]);
        if (ret < 0) return -1;
        aes_hex_in[i] += ret;
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in[i]);
    }

    memset(aes_hex_out, 0, AES_B64_BUF_LEN);
#ifdef GCC_X86
    AES_set_decrypt_key(secret_ctx->key, sizeof(secret_ctx->key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, in->len/2, &dec_key, secret_iv, AES_DECRYPT);
#else 
    ret = esp_aes_crypt_cbc((esp_aes_context*) secret_ctx,       // AES context
                            ESP_AES_DECRYPT,  // AES_ENCRYPT or AES_DECRYPT
                            in->len/2,        // length of the input data
                            secret_iv,        // initialization vector (updated after use)       
                            aes_hex_in,       // buffer holding the input data
                            aes_hex_out);     // buffer holding the output data
//  return 0 if successful, or ERR_AES_INVALID_INPUT_LENGTH       
    if (ret) {
        ESP_LOGE("secret", "esp_aes_crypt_cbc aes_hex_in failed, ret = %d", ret); 
        return -1;
    }
#endif /* GCC_X86 */

    out->len = in->len/2;
    bzero(out->u_str, out->len);
    for (int i=0; i<out->len; i++) out->u_str[i] = aes_hex_out[i];

    return 0;    
}


#endif