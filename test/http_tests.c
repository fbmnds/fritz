#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <openssl/sha.h>

#define TEST 1

#define ESP_LOGI(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")
#define ESP_LOGE(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")

typedef struct str_p {
    char* str;
    int  len;
} str_pt;

#include "test_secrets.h"

#define SHA2_256 0
void esp_sha(int sha_type, const unsigned char *input, size_t ilen, unsigned char *output)
{
	unsigned char *o;

	memset(output, 0 , 32);
	o = SHA256(input, ilen, output);
	return;
}

#include "../main/http/http_globals.h"
#include "../main/http/http_upload.h"


static char recv_buf[HTTP_RECV_BUF_LEN];

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

void test1(void)
{
	str_pt fn;
	int ret;
	const char test[] = "test.txt";
	const char test_recv_buf[] = TEST_RECV_BUF;
	str_pt recv_p;

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = (char *) test_recv_buf;
	recv_p.len = strlen(test_recv_buf);
	cp_str_head(recv_buf, &recv_p);

	ret = upload_fn (&fn, recv_buf, upload_url);

	assert(ret == 0);
	assert(fn.len == strlen(test));
	for (int i=0; i<fn.len; i++) assert(test[i] == fn.str[i]);
	assert(test[strlen(test)] == '\0');	
	printf("test1: cp_str_head, upload_fn passed\n");
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
    printf("test2: cp_str_head, set_payload_idx passed\n");
    return;
fail:
	printf("idx = %d; in_len = %d, no payload\n", idx, in_len);
	assert(0 == 1);
	return; 
}

void test3 (void)
{
	char test_recv_buf[TEST_RECV_BUF_MAX_LEN];
	const char test2[] = TEST_RECV_BUF;
	str_pt recv_p;
	int in_len, test2_len, mod_key_size;
	unsigned char out[160];
	int out_len;

	char out2[320];
	int out2_len;

	out_len = 160;
	out2_len = 320;

	test2_len = strlen(test2);

	mod_key_size = test2_len % AES_KEY_SIZE;	

	assert(TEST_RECV_BUF_MAX_LEN >= (test2_len + AES_KEY_SIZE - mod_key_size));

	memset(test_recv_buf, 0, TEST_RECV_BUF_MAX_LEN);
	recv_p.str = (char *) test2;
	recv_p.len = test2_len;
	cp_str_head(test_recv_buf, &recv_p);
	if (mod_key_size) 
		test2_len = test2_len + AES_KEY_SIZE - mod_key_size;

	assert(test2_len == 80);
	assert(out2_len >= 2*test2_len);
	assert(out2_len % AES_KEY_SIZE == 0);
	assert(out2_len <= sizeof(out2));

    aes128_cbc_encrypt(test_recv_buf, test2_len, out2, &out2_len);


    // printf("test_recv_buf[0] %2x\n", test_recv_buf[0]);
    // printf("'");
    // for (int i=0; i<test2_len; i++) 
    // 	printf("%c", test_recv_buf[i]);
    // printf("'\n");	    

    
    // printf("'");
    // for (int i=0; i<out2_len; i++) 
    // 	printf("%c", out2[i]);
    // printf("'\n");	
    
    assert(out_len>2*in_len); /* with terminating '\0' */

    memset(out, 0, out_len);
    aes128_cbc_decrypt2(out2, out2_len, out);
    
    // printf("'");
    // for (int i=0; i<strlen(out); i++) 
    // 	printf("%c", out[i]);
    // printf("'\n");
    
    for (int i=0; i<out2_len; i++) assert(out[i] == test_recv_buf[i]);
    printf("test3: aes128_cbc_encrypt, aes128_cbc_decrypt passed\n");
}


    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;1;on
    //     4    9    14   19   24   29

void test4 (const char* req, const char* req_decrypt)
{
	int in_len;
	unsigned char out[320];
	int out_len;

	char out2[320];
	int out2_len;

	int ret;

	out_len = 320;
	out2_len = 320;

	in_len = strlen(req_decrypt);
	in_len = in_len + AES_KEY_SIZE - in_len%AES_KEY_SIZE;

	assert(in_len == 48);

	assert(out2_len>=2*in_len);
	assert(out2_len % AES_KEY_SIZE == 0);
	assert(out2_len>=sizeof(out2));
    
    aes128_cbc_encrypt(req_decrypt, in_len, out2, &out2_len);

    assert(out_len>2*in_len); /* with terminating '\0' */
    //for (int i=0; i<strlen(req_decrypt); i++)  printf("%c", req_decrypt[i]);  printf("\n");
    //for (int i=0; i<strlen(out2); i++) printf("%c", out2[i]); printf("\n");
    for (int i=0; i<strlen(out2); i++) assert(out2[i] == req[i]);

    memset(out, 0, out_len);
    aes128_cbc_decrypt2(out2, out2_len, out);
    
    for (int i=0; i<strlen(out); i++) assert(out[i] == req_decrypt[i]);

    printf("test4: aes128_cbc_encrypt, aes128_cbc_decrypt passed\n");
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

	aes128_cbc_decrypt2(recv_p.str, recv_p.len, recv_p.str);
	
	assert(strlen(recv_p.str) == strlen(test2));
	for (int i=0; i<strlen(test2); i++) assert(test2[i] == recv_p.str[i]);

	printf("test5: cp_str_head, set_payload_idx2, aes128_cbc_decrypt2 passed\n");
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

	aes128_cbc_decrypt3(&recv_p, &recv_p);
	
	assert(strlen(recv_p.str) == strlen(test2));
	for (int i=0; i<strlen(test2); i++) assert(test2[i] == recv_p.str[i]);

	for (int i=0; i<strlen(test_recv_buf); i++) assert(test_recv_buf[i] == test_recv_buf_decrypt[i]);

	assert (validate_req_base(&recv_p) == -15);

	printf("test6: cp_str_head, set_payload_idx2, aes128_cbc_decrypt3, validate_req_base passed\n");

	recv_p.str = (char *) test3;
	esp_sha(SHA2_256, (unsigned char *) recv_p.str, REGISTER_ITEM_LEN*2, out);
	// printf("out '");
	// for (int i=0; i<32; i++) printf("%02x", out[i]);
	// printf("'\n");
	// printf("sha '4377225503e0929e435914a6894eeea02fabedf37a58d2a4a3c74f91550bcd9b'\n");
	printf("test6: SHA256 failed\n");
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

	printf("test7: passed\n");
}

void test8(const char* req, const char* req_decrypt)
{
	char recv_buf[HTTP_RECV_BUF_LEN];
	char recv_buf_decrypt[HTTP_RECV_BUF_LEN];
	str_pt recv_p;

	http_server_label_t ret;

	sprintf(API_KEY, "0000-0000-0000");

    static char req_register[REGISTER_ITEM_LEN*REGISTER_LEN];
    int register_idx = -1;

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

	aes128_cbc_decrypt3(&recv_p, &recv_p);
	
	assert(strlen(recv_p.str) == strlen(req_decrypt));
	for (int i=0; i<strlen(req_decrypt); i++) assert(req_decrypt[i] == recv_p.str[i]);

	for (int i=0; i<strlen(recv_buf); i++) assert(recv_buf[i] == recv_buf_decrypt[i]);

	assert (validate_req_base(&recv_p) == 0);

	//assert(register_req(req_register, &register_idx, &recv_p) == 0); // TODO

	printf("test8: passed\n");
}

int main(void)
{
	test1();
	test2();
	test3();
	const char req_decrypt[] = "xxxx-xxxx-xxxx;yyyy-yyyy-yyyy;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	                           //   4    9    14   19   24   29
	const char req[] = "262c6d8baa84549ac2a089d9825220a09f53955aa5f4fd9dca89785b39ebbd3b42af884c8bab89300f7ea122a9016f2f";
	test4(req, req_decrypt);
	const char req_decrypt_0[] = "0000-0000-0000;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_0[] = "a39f7dd2a1edd5bb6a20e87466429efa21fc4c53d3eb183d793fa991e6400e0363649b1f0953ff65d777b04162d2f97c";
	test4(req_0, req_decrypt_0);
	const char req_decrypt_1[] = "1111-1111-1111;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_1[] = "1e45fb4ee99101b2438cb5c33131f0fb62620bf3cbc461d2bd1c2ab69f91fc92740fc007465488df7915d1fb11e49512";
	test4(req_1, req_decrypt_1);
	const char req_decrypt_2[] = "2222-2222-2222;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_2[] = "5025d9a0a0b92bb4fc8bf39d688042bd432067def7ba9457caa32eff8ba9a5beb6c7fe88b9d71a6965651f7813be6d09";
	test4(req_2, req_decrypt_2);
	const char req_decrypt_3[] = "3333-3333-3333;0000-0000-0000;1;on\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	const char req_3[] = "72d246bb9ffb87779b00989163ab6be3ad9865368bf664fb1249efff9e9a2e0151e84f8d3cceb0cf60929f7d166c3603";
	test4(req_3, req_decrypt_3);
	test5();
	test6();
	test7();
	//test8(req, req_decrypt);
	test8(req_0, req_decrypt_0);
	test8(req_1, req_decrypt_1);
	test8(req_2, req_decrypt_2);
	test8(req_3, req_decrypt_3);
}
