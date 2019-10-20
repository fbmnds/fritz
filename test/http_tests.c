#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>


#define TEST 1
#define VERBOSE 1

#define GCC_X86  1

#ifdef GCC_X86

#include <openssl/sha.h>

#ifdef  VERBOSE
#define ESP_LOGI(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")
#define ESP_LOGE(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")
#else
#define ESP_LOGI(a, b, ...) 
#define ESP_LOGE(a, b, ...) 
#endif /* VERBOSE */

#define p_green(b, ...) printf("\n\033[1;32m");printf(b, ##__VA_ARGS__);printf("\033[1;0m")
#define p_red(b, ...)   printf("\n\033[1;31m");printf(b, ##__VA_ARGS__);printf("\033[1;0m")

#define SHA2_256 0
void esp_sha(int sha_type, const unsigned char *input, size_t ilen, unsigned char *output)
{
	unsigned char *o;

	memset(output, 0 , 32);
	o = SHA256(input, ilen, output);
	return;
}

typedef struct {
    uint8_t key_bytes;
    uint8_t key[32];
} esp_aes_context;

#endif /* GCC_X86 */

#include "test_secrets.h"

#include "../main/http/http_globals.h"
#include "../main/http/http_upload.h"

static char recv_buf[HTTP_RECV_BUF_LEN];

static str_pt api_key    = { .str = API_KEY,    .len = API_KEY_LEN };
static str_pt upload_key = { .str = UPLOAD_KEY, .len = API_KEY_LEN };
extern FILE * upload_file;

#define TEST_RECV_BUF_MAX_LEN 256
#define TEST_RECV_BUF "POST /upload/test.txt HTTP/1.1\r\nContent-Length: 123\r\n\r\n0123456789abcdef\r\n"
	//                          0         0          0           0         0             0         0

#define TEST2_RECV_BUF \
"POST /upload/test.txt HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f\r\n"

#define TEST2_RECV_BUF_DECRYPT \
"POST /upload/test.txt HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on"

#define TEST2_RECV_BUF_LEN strlen(TEST2_RECV_BUF)
#define TEST2_RECV_BUF_DECRYPT_LEN strlen(TEST2_RECV_BUF_DECRYPT)

#define TEST3_RECV_BUF \
"POST /upload/test.txt HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"%s\r\n"

#define TEST3_RECV_BUF_DECRYPT \
"POST /upload/test.txt HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"%s"

#define TEST4_RECV_BUF \
"POST /upload/%s HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"%s\r\n"

#define TEST4_RECV_BUF_DECRYPT \
"POST /upload/%s HTTP/1.1\r\n" \
"Content-Length: 123\r\n\r\n" \
"%s"

#define TEST_TXT "/test.txt"
#define TEST_TXT_ENCR "dfd13cfc897eb9d35480179b3876cda5"

void test1(void)
{
	str_pt fn;

	const char test[] = "test.txt";
	const char test_recv_buf[] = TEST_RECV_BUF;
	str_pt recv_p;

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = (char *) test_recv_buf;
	recv_p.len = strlen(test_recv_buf);
	cp_str_head(recv_buf, &recv_p);

	p_green("test1: cp_str_head passed\n");
}


void test2 (void)
{
	int idx, in_len;
	const char test_recv_buf[] = TEST_RECV_BUF;

	const char test[] = "0123456789abcdef";
	str_pt recv_p;

	in_len = strlen(test);

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = (char *) test_recv_buf;
	recv_p.len = strlen(test_recv_buf);
	cp_str_head(recv_buf, &recv_p);

	switch (set_payload_idx (&idx, &in_len, recv_buf)) {
        case CONTINUE: break;
        default:   goto fail;
    }
    assert(idx == 55);
    assert(in_len == 16);
    for (int i=0; i<in_len; i++ ) assert(test[i] == recv_buf[idx+i]);
    p_green("test2: cp_str_head, set_payload_idx passed\n");
    return;
fail:
	p_red("idx = %d; in_len = %d, no payload\n", idx, in_len);
	assert(0 == 1);
	return; 
}

void test3 (const char* req, const char* req_decrypt)
{
	unsigned char iv[AES_KEY_SIZE];
	
	unsigned char out_str[320];
	str_pt out = { .str = out_str, .len = 320 };

	char out2_str[320];
	str_pt out2 = { .str = out2_str, .len = 320 };

	int in_len;

	in_len = strlen(req_decrypt);
	in_len = in_len + AES_KEY_SIZE - in_len%AES_KEY_SIZE;
	assert(in_len == 48);

	assert(out2.len>=2*in_len);
	assert(out2.len % AES_KEY_SIZE == 0);
	assert(out2.len>=sizeof(out2));
    
	for (int i = 0; i < AES_KEY_SIZE; i++) iv[i] = IV[i];

    aes128_cbc_encrypt(req_decrypt, in_len, out2.str, &out2.len, &secret_ctx, iv);
	//for (int i = 0; i < AES_KEY_SIZE; i++) iv[i] = IV[i];

	assert(out2.len == 2*in_len);
	for (int i=0; i< in_len; i++) assert(req[i] == out2.str[i]);

    p_green("test3: aes128_cbc_encrypt passed\n");
}


    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;1;on
    //     4    9    14   19   24   29

void test4 (const char* req, const char* req_decrypt)
{
	unsigned char iv[AES_KEY_SIZE];
	
	int in_len;

	unsigned char out_str[320];
	str_pt out = { .str = out_str, .len = 320 };

	char out2_str[320];
	str_pt out2 = { .str = out2_str, .len = 320 };

	int ret;

	in_len = strlen(req_decrypt);
	in_len = in_len + AES_KEY_SIZE - in_len%AES_KEY_SIZE;
	assert(in_len == 48);

	assert(out2.len>=2*in_len);
	assert(out2.len % AES_KEY_SIZE == 0);
	assert(out2.len>=sizeof(out2));
    
	for (int i = 0; i < AES_KEY_SIZE; i++) iv[i] = IV[i];
    aes128_cbc_encrypt(req_decrypt, in_len, out2.str, &out2.len, &secret_ctx, iv);
	

	assert(out2.len == 2*in_len);
	
	for (int i=0; i<2*in_len; i++) assert(req[i] == out2.str[i]);


    memset(out.str, 0, out.len);

	for (int i = 0; i < AES_KEY_SIZE; i++) iv[i] = IV[i];
    ret = aes128_cbc_decrypt3(&out2, &out, &secret_ctx, iv);
    
    assert(ret == 0);
    assert(in_len == out.len);

    for (int i=0; i<out.len; i++) {
    	//printf("out.str[%d] '%c', req_decrypt[%d] '%c'\n", i, out.str[i], i, req_decrypt[i]);
    	assert(out.str[i] == req_decrypt[i]);
    }
    		
    p_green("test4: aes128_cbc_encrypt, aes128_cbc_decrypt3 passed\n");
}

void test5 (void)
{
	char test_recv_buf[HTTP_RECV_BUF_LEN];
	const char test[] = "262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f";
	const char test2[] = "xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on";

	char req[] = TEST2_RECV_BUF;
	str_pt recv_p;

	int idx, in_len;

	http_server_label_t ret;

	memset(test_recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = req;
	recv_p.len = TEST2_RECV_BUF_LEN;
	cp_str_head(test_recv_buf, &recv_p);

	recv_p.str = NULL;
	recv_p.len = 0;	
	ret = set_payload_idx2(&recv_p, test_recv_buf);

	assert(ret == CONTINUE);
	assert(recv_p.str[0] == '2');
	assert(recv_p.len == strlen(test));
	for (int i=0; i<recv_p.len; i++) assert(test[i] == recv_p.str[i]);

	aes128_cbc_decrypt3(&recv_p, &recv_p, &secret_ctx, IV);
	
	assert(strlen(recv_p.str) == strlen(test2));
	for (int i=0; i<strlen(test2); i++) assert(test2[i] == recv_p.str[i]);

	p_green("test5: cp_str_head, set_payload_idx2, aes128_cbc_decrypt3 passed\n");
}

void test6 (void)
{
	char test_recv_buf[HTTP_RECV_BUF_LEN];
	const char test_recv_buf_decrypt[] = TEST2_RECV_BUF_DECRYPT;
	const char test[] = "262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f";
	const char test2[] = "xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on";
	const char test3[] = "xxxx-xxxx-xxxx";
	unsigned char out[64];

	char req[] = TEST2_RECV_BUF;
	str_pt recv_p;

	http_server_label_t ret;

	memset(test_recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = req;
	recv_p.len = TEST2_RECV_BUF_LEN;
	cp_str_head(test_recv_buf, &recv_p);

	recv_p.str = NULL;
	recv_p.len = 0;	
	ret = set_payload_idx2(&recv_p, test_recv_buf);

	assert(ret == CONTINUE);
	assert(recv_p.str[0] == '2');
	assert(recv_p.len == strlen(test));
	for (int i=0; i<recv_p.len; i++) assert(test[i] == recv_p.str[i]);

	aes128_cbc_decrypt3(&recv_p, &recv_p, &secret_ctx, IV);
	
	assert(strlen(recv_p.str) == strlen(test2));
	for (int i=0; i<strlen(test2); i++) assert(test2[i] == recv_p.str[i]);

	for (int i=0; i<strlen(test_recv_buf); i++) assert(test_recv_buf[i] == test_recv_buf_decrypt[i]);

	assert (validate_req_base(&recv_p, &api_key) == -15);

	p_green("test6: cp_str_head, set_payload_idx2, aes128_cbc_decrypt3, validate_req_base passed\n");

	recv_p.str = (char *) test3;
	esp_sha(SHA2_256, (unsigned char *) recv_p.str, REGISTER_ITEM_LEN*2, out);
	// printf("out '");
	// for (int i=0; i<32; i++) printf("%02x", out[i]);
	// printf("'\n");
	// printf("sha '4377225503e0929e435914a6894eeea02fabedf37a58d2a4a3c74f91550bcd9b'\n");
	p_red("test6: SHA256 failed\n");
}

void test7(void)
{
	const char req_decrypt[] = "xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	                           //   4    9    14   19   24   29
	const char req[] = "262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f";

	char recv_buf[HTTP_RECV_BUF_LEN];
	char recv_buf_decrypt[HTTP_RECV_BUF_LEN];

	const char recv_buf_2[] = TEST2_RECV_BUF;
	const char recv_buf_decrypt_2[] = TEST2_RECV_BUF_DECRYPT;

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf,TEST3_RECV_BUF, req);
	for (int i=0; i<TEST2_RECV_BUF_LEN+1; i++) assert(recv_buf[i] == recv_buf_2[i]);

	memset(recv_buf_decrypt, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf_decrypt,TEST3_RECV_BUF_DECRYPT, req_decrypt);
	for (int i=0; i<TEST2_RECV_BUF_DECRYPT_LEN+1; i++) assert(recv_buf_decrypt[i] == recv_buf_decrypt_2[i]);

	p_green("test7: building HTTP 200 with sprintf passed\n");
}

void test8(const char* req, const char* req_decrypt,
	       char* req_register, int* register_idx)
{
	char recv_buf[HTTP_RECV_BUF_LEN];
	char recv_buf_decrypt[HTTP_RECV_BUF_LEN];
	str_pt recv_p;

	http_server_label_t ret;

	int rc;

	sprintf(API_KEY, "0000-0000-0000");

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf,TEST3_RECV_BUF, req);

	memset(recv_buf_decrypt, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf_decrypt,TEST3_RECV_BUF_DECRYPT, req_decrypt);

	recv_p.str = NULL;
	recv_p.len = 0;	
	ret = set_payload_idx2(&recv_p, recv_buf);
	
	//for (int i=0; i<strlen(recv_buf); i++) printf("%c", recv_buf[i]); printf("\n");

	assert(ret == CONTINUE);
	//for (int i=0; i<recv_p.len; i++) printf("%c", recv_p.str[i]); printf("\n");
	//for (int i=0; i<strlen(req); i++) printf("%c", req[i]); printf("\n");
	assert(recv_p.str[0] == req[0]);
	assert(recv_p.len == strlen(req));
	for (int i=0; i<recv_p.len; i++) assert(req[i] == recv_p.str[i]);

	aes128_cbc_decrypt3(&recv_p, &recv_p, &secret_ctx, IV);
	
	assert(strlen(recv_p.str) == strlen(req_decrypt));
	for (int i=0; i<recv_p.len; i++) printf("%c", recv_p.str[i]); printf("\n");
	for (int i=0; i<strlen(req_decrypt); i++) printf("%c", req_decrypt[i]); printf("\n");	
	for (int i=0; i<strlen(req_decrypt); i++) assert(req_decrypt[i] == recv_p.str[i]);

	for (int i=0; i<strlen(recv_buf); i++) assert(recv_buf[i] == recv_buf_decrypt[i]);

	assert (validate_req_base(&recv_p, &api_key) == 0);

	rc = register_req(req_register, register_idx, &recv_p);
	assert(rc == 0);

	p_green("test8: validate_req_base, register_req passed\n");
}

void test9 ()
{
	char recv_buf[HTTP_RECV_BUF_LEN];
	const char test[] = "262c6d8baa84549ac2a089d9825220a0";
	const unsigned char u_test[] = { 0x26, 0x2c, 0x6d, 0x8b, 0xaa, 0x84, 0x54, 0x9a, 
	                                 0xc2, 0xa0, 0x89, 0xd9, 0x82, 0x52, 0x20, 0xa0 };
	const char test_encrypt[] = "42b7846e0a73e64b12054ce59880f4ceeab619e9b77f83bd6bb4f690d57551a0";

	char test_decr4[AES_KEY_SIZE*4];

	str_pt   recv_p;
	u_str_pt out;

	int ret;


	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);

	for (int i=0; i<AES_KEY_SIZE; i++) 
		sprintf(recv_buf+2*API_KEY_LEN+2+i*2, "%02x", u_test[i]); 

	recv_p.str = recv_buf+2*API_KEY_LEN+2;
	recv_p.len = AES_KEY_SIZE*2;
	assert(strlen(test) == AES_KEY_SIZE*2);
//	printf("%s\n", recv_buf+2*API_KEY_LEN+2);
	assert(strlen(test) == strlen(recv_buf+2*API_KEY_LEN+2));
	assert(strstr(recv_buf+2*API_KEY_LEN+2,test));

	aes128_cbc_encrypt(recv_p.str, recv_p.len, recv_p.str, &recv_p.len, &secret_ctx, IV);
//	printf("%s\n", recv_buf+2*API_KEY_LEN+2);

	memset(test_decr4, 0, AES_KEY_SIZE*4);
	out.u_str = test_decr4;
	out.len = AES_KEY_SIZE*4;
	ret = aes128_cbc_decrypt4(&recv_p, &out, &secret_ctx, IV);

	assert(ret == 0);
//	printf("out.len = %d\n", out.len);
	assert(out.len == AES_KEY_SIZE*2);
//	printf("out.str %s\n", out.u_str);
//	for (int i=0; i<AES_KEY_SIZE; i++) printf("out.u_str[i] %02x u_test[i] %02x \n", out.u_str[i], u_test[i]);

    for (int i=0; i<out.len/2; i++) {
        ret = ctoi(out.u_str[2*i]);
        assert(ret >= 0);
        recv_p.str[i] = ret*16;
        ret = ctoi(out.u_str[2*i+1]);
        assert(ret >= 0);
        recv_p.str[i] += ret;
        //ESP_LOGI("SECRET: ", "aes_hex_in %x", (int) aes_hex_in[i]);
    }
    recv_p.len = out.len/2;

    assert(recv_p.len == strlen(test)/2);
//	for (int i=0; i<AES_KEY_SIZE; i++) printf("(uint8_t)recv_p.str[i] %02x u_test[i] %02x \n", (uint8_t)recv_p.str[i], u_test[i]);
    for (int i=0; i<recv_p.len; i++) assert(u_test[i] == (uint8_t)recv_p.str[i]);

    p_green("test9: aes128_cbc_decrypt4 passed\n");	
}

void test10 (const char* req, const char* req_decrypt)
{
	char recv_buf[HTTP_RECV_BUF_LEN];
	str_pt recv_p;

	http_server_label_t ret;


	sprintf(API_KEY, "0000-0000-0001");

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf,TEST3_RECV_BUF, req);

	ret = post_upload(0, recv_buf, strlen(recv_buf));
	//for (int i=0; i<out2_len; i++) printf("%c", out2[i]); printf("\n");
    
	assert(ret == _500);

	sprintf(API_KEY, "0000-0000-0000");

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf,TEST4_RECV_BUF, TEST_TXT_ENCR, req);


	sprintf(SD_PREFIX, "%s", "./build");
	assert(strlen(SD_PREFIX) <= SD_PREFIX_LEN);

	ret = post_upload(0, recv_buf, strlen(recv_buf));
	//for (int i=0; i<out2_len; i++) printf("%c", out2[i]); printf("\n");
    
	assert(ret == DONE);
	for (int i=0; i<API_KEY_LEN; i++) assert(UPLOAD_KEY[i] == req_decrypt[i]);
	//for (int i=0; i<API_KEY_LEN; i++) printf("%c", UPLOAD_KEY[i]); printf("\n");

	assert(upload_file_len == 1);
	assert(upload_file);
	fclose(upload_file);

    p_green("test10: post_upload passed\n");	
}


void test11 (const char* req, const char* req_decrypt)
{
	char recv_buf[HTTP_RECV_BUF_LEN];
	str_pt recv_p;

	http_server_label_t ret;

	sprintf(API_KEY,      "0000-0000-0000");
	sprintf(UPLOAD_KEY,   "1000-0000-0000");
	sprintf(UPLOAD_NONCE, "3000-0000-0000");



	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	sprintf(recv_buf,TEST4_RECV_BUF, TEST_TXT_ENCR, req);


	sprintf(SD_PREFIX, "%s", "./build");
	assert(strlen(SD_PREFIX) <= SD_PREFIX_LEN);

	ret = post_upload(0, recv_buf, strlen(recv_buf));
	//for (int i=0; i<out2_len; i++) printf("%c", out2[i]); printf("\n");
    
	assert(ret == DONE);
	for (int i=0; i<API_KEY_LEN; i++) assert(UPLOAD_KEY[i] == req_decrypt[i]);
	//for (int i=0; i<API_KEY_LEN; i++) printf("%c", UPLOAD_KEY[i]); printf("\n");

	assert(upload_file_len == 1);
	assert(upload_file);
	fclose(upload_file);
	
    p_green("test11: post_put passed\n");	
}

int main(void)
{
	test1();
	const char req_decrypt[] = "xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	                           //   4    9    14   19   24   29
	const char req[] = "262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f";
	
	char req_decrypt_0[] = "0000-0000-0000;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	char req_0[] = "a39f7dd2a1edd5bb6a20e87466429efa21fc4c53d3eb183d793fa991e6400e0363649b1f0953ff65d777b04162d2f97c";
	const char req_decrypt_1[] = "1111-1111-1111;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_1[] = "1e45fb4ee99101b2438cb5c33131f0fb62620bf3cbc461d2bd1c2ab69f91fc92740fc007465488df7915d1fb11e49512";
	const char req_decrypt_2[] = "2222-2222-2222;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_2[] = "5025d9a0a0b92bb4fc8bf39d688042bd432067def7ba9457caa32eff8ba9a5beb6c7fe88b9d71a6965651f7813be6d09";
	const char req_decrypt_3[] = "3333-3333-3333;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_3[] = "72d246bb9ffb87779b00989163ab6be3ad9865368bf664fb1249efff9e9a2e0151e84f8d3cceb0cf60929f7d166c3603";
	test3(req, req_decrypt);
    test3(req_0, req_decrypt_0);
    test3(req_1, req_decrypt_1);
	test3(req_2, req_decrypt_2);    
	test3(req_3, req_decrypt_3);	

	test4(req, req_decrypt);
    test4(req_0, req_decrypt_0);
    test4(req_1, req_decrypt_1);
	test4(req_2, req_decrypt_2);    
	test4(req_3, req_decrypt_3);

	test5();
	test6();
	test7();
	static char req_register[REGISTER_ITEM_LEN*REGISTER_LEN+1];
	int register_idx = 0;	

	test8(req_1, req_decrypt_1, req_register, &register_idx);
	assert(register_idx == 1);
	test8(req_2, req_decrypt_2, req_register, &register_idx);
	assert(register_idx == 2);
	test8(req_3, req_decrypt_3, req_register, &register_idx);
	assert(register_idx == 3);

	memset(req_register, 0, REGISTER_ITEM_LEN*REGISTER_LEN+1);
	register_idx = 0;
	str_pt str;
	str.str = req_0;
	str.len = 48;
	req_decrypt_0[0] = '1'; 
	for (int i=0; i<2*REGISTER_LEN+3; i++) {
		req_decrypt_0[11] = '0' + i/100;
		req_decrypt_0[12] = '0' + i/10;
		req_decrypt_0[13] = '0' + i%10;
		//printf("strlen(req_decrypt_0) %ld\n", strlen(req_decrypt_0));
		aes128_cbc_encrypt(req_decrypt_0, 48, str.str, &str.len, &secret_ctx, IV);
		test8(req_0, req_decrypt_0, req_register, &register_idx);
		if (i == 0) 
			assert(register_idx == 1);
		else {
			//printf("i %d register_idx %d \n", i, register_idx);
			assert(register_idx == i%REGISTER_LEN+1);
		}         
		printf("(i%%REGISTER_LEN+1)*REGISTER_ITEM_LEN) %d\n", (i%REGISTER_LEN+1)*REGISTER_ITEM_LEN);
		printf("strlen(req_register) %ld\n", strlen(req_register));
		assert(req_register[REGISTER_LEN*REGISTER_LEN] == '\0');

	    if (64 == i) {
				printf("i %d register_idx %d \n", i, register_idx);
				assert(strlen(req_register) == REGISTER_ITEM_LEN);
		}  else {
		    assert(strlen(req_register) == (i%REGISTER_LEN+1)*REGISTER_ITEM_LEN);
		}
	}
	test9();
	test10(req_1, req_decrypt_1);

}
