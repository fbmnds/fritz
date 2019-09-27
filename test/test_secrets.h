#ifndef _TEST_SECRETS_H_
#define _TEST_SECRETS_H_

#include <openssl/aes.h>

#define AES_ENCRYPT     1
#define AES_DECRYPT     0

#define AES_B64_BUF_LEN   1024
#define AES_B64_BUF_LEN_2 2048
#define AES_KEY_SIZE        16

#define API_KEY_LEN 14
static char API_KEY[]      = "0000-0000-0000";

#define IV {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00}

typedef struct {
    uint8_t key_bytes;
    uint8_t key[32];
} esp_aes_context;

static esp_aes_context secret_ctx = {
    .key_bytes = AES_KEY_SIZE,
    .key = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}
};


static unsigned char aes_hex_in[AES_B64_BUF_LEN];
static unsigned char aes_hex_out[AES_B64_BUF_LEN];

void aes128_cbc_encrypt(const char *in, int in_len, char *out2, int *out2_len)
{
	int ret, mod_key_size;
	size_t in_len2;
    unsigned char iv[] = IV;
    AES_KEY enc_key;

	assert(in_len % AES_KEY_SIZE == 0);
    in_len2 = (size_t) in_len;
	
    //ESP_LOGI("SECRET: ", "aes128_cbc_encrypt i n_len2 = %ld\n%s\n", in_len2, in);

	bzero(aes_hex_in, sizeof(aes_hex_in));
	for (int i=0; i<in_len; i++) aes_hex_in[i] = (unsigned char) in[i];

    bzero(aes_hex_out, sizeof(aes_hex_out));
	bzero(out2, *out2_len);


    AES_set_encrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &enc_key);
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &enc_key, iv, AES_ENCRYPT);


	for (size_t i=0; i<in_len2; i++) {
		sprintf(out2+i*2, "%02x", aes_hex_out[i]);
	} 
    *out2_len = 2*in_len2;
}

uint8_t ctoi (char c)
{
    if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
    if (c >= 'A' && c <= 'F') return (uint8_t) (10 + c - 'A');
    if (c >= 'a' && c <= 'f') return (uint8_t) (10 + c - 'a');
    return -1;
}


void aes128_cbc_decrypt(const char *in, int in_len, unsigned char *out2)
{
    int ret;
    uint8_t *aes_hex_in_8;
    unsigned char iv[] = IV;
    AES_KEY dec_key;

    if (in_len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "esp_aes_crypt_cbc aes_hex_in failed, in_len = %d", in_len);
        return;
    }

    aes_hex_in_8 = (uint8_t *) aes_hex_in;
    bzero(aes_hex_in, sizeof(aes_hex_in));
    for (int i=0; i<in_len/2; i++) {
        aes_hex_in_8[i] = ctoi(in[2*i])*16 + ctoi(in[2*i+1]);
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in_8[i]);
    }

    bzero(out2, in_len/2+1);
    AES_set_decrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &dec_key, iv, AES_DECRYPT);

    /* copy with terminating '\0' */
    for (int i=0; i<=strlen(aes_hex_out) ; i++) out2[i] = aes_hex_out[i]; 

    return;    
}


void aes128_cbc_decrypt2(const char *in, int in_len, char *out2)
{
    int ret;
    uint8_t *aes_hex_in_8;
    unsigned char iv[] = IV;
    AES_KEY dec_key;

    if (in_len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "esp_aes_crypt_cbc aes_hex_in failed, in_len = %d", in_len);
        return;
    }

    aes_hex_in_8 = (uint8_t *) aes_hex_in;
    bzero(aes_hex_in, sizeof(aes_hex_in));
    for (int i=0; i<in_len/2; i++) {
        aes_hex_in_8[i] = ctoi(in[2*i])*16 + ctoi(in[2*i+1]);
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in_8[i]);
    }

    bzero(out2, in_len);
    AES_set_decrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &dec_key, iv, AES_DECRYPT);

    /* copy with terminating '\0' */
    for (int i=0; i<=strlen(aes_hex_out) ; i++) out2[i] = (char) aes_hex_out[i]; 

    return;    
}


int aes128_cbc_decrypt3(str_pt *in, str_pt *out)
{
    int ret;
    uint8_t *aes_hex_in_8;
    unsigned char iv[] = IV;
    AES_KEY dec_key;

    assert(in->len <= out->len);

    if (in->len%AES_KEY_SIZE) {
        ESP_LOGE("SECRET: ", "esp_aes_crypt_cbc aes_hex_in failed, in_len = %d", in->len);
        return -1;
    }

    aes_hex_in_8 = (uint8_t *) aes_hex_in;
    bzero(aes_hex_in, sizeof(aes_hex_in));
    for (int i=0; i<in->len/2; i++) {
        aes_hex_in_8[i] = ctoi(in->str[2*i])*16 + ctoi(in->str[2*i+1]);
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in_8[i]);
    }

    
    AES_set_decrypt_key(secret_ctx.key, sizeof(secret_ctx.key)*8, &dec_key); // Size of key is in bits
    AES_cbc_encrypt(aes_hex_in, aes_hex_out, sizeof(aes_hex_in), &dec_key, iv, AES_DECRYPT);

    bzero(out->str, in->len);
    /* copy with terminating '\0' */
    for (int i=0; i<=strlen(aes_hex_out) ; i++) out->str[i] = (char) aes_hex_out[i];
    out->len = strlen(out->str); 

    return 0;    
}

#endif