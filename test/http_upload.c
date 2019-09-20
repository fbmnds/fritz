#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#define ESP_LOGI(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")
#define ESP_LOGE(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__);printf("\n")

void aes128_cbc_decrypt(const char *in, int in_len, unsigned char *out2)
{
	return;
}

#define API_KEY_LEN 14
static char API_KEY[]      = "______________";

#define SHA2_256 0
void esp_sha(int sha_type, const unsigned char *input, size_t ilen, unsigned char *output)
{
	return;
}

#include "../main/http/http_globals.h"
#include "../main/http/http_upload.h"


static char recv_buf[HTTP_RECV_BUF_LEN];

void test1(void)
{
	str_pt fn;
	int ret;
	const char test[] = "test.txt";
	const char test_recv_buf[] = "POST /upload/test.txt HTTP/1.1\r\nContent-Length: 123\r\n\r\n0123456789abcdef\r\n";
	str_pt recv_p;

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = test_recv_buf;
	recv_p.len = strlen(test_recv_buf);
	cp_str_head(recv_buf, &recv_p);

	ret = upload_fn (&fn, recv_buf, upload_url);
	printf("ret %d, fn.len %d, fn.str: '", ret, fn.len);
	for (int i=0; i<fn.len; i++) printf("%c", fn.str[i]);
	printf("'\nstrlen = %ld\n", strlen(test));
	printf("test[9] = %d\n", test[9]);
	printf("recv_buf[strlen] = %d\n", recv_buf[strlen(recv_buf)]);
	printf("recv_buf[strlen++] = %d\n", recv_buf[strlen(recv_buf)+1]);
}


void test2 (void) 
{
   char str[80] = "This is - www.tutorialspoint.com - website";
   const char s[2] = "-";
   char *token;
   
   /* get the first token */
   token = strtok(str, s);
   
   /* walk through other tokens */
   while( token != NULL ) {
      ESP_LOGI("test2", " %s", token );  
      token = strtok(NULL, s);
   }
   
   return;
}


void test3 (void)
{
	int idx, in_len;
	const char test_recv_buf[] = "POST /upload/test.txt HTTP/1.1\r\nContent-Length: 123\r\n\r\n0123456789abcdef\r\n";
	//                                     0         0          0           0         0             0         0
	str_pt recv_p;

	memset(recv_buf, 0, HTTP_RECV_BUF_LEN);
	recv_p.str = test_recv_buf;
	recv_p.len = strlen(test_recv_buf);
	cp_str_head(recv_buf, &recv_p);

	switch (set_payload_idx (&idx, &in_len, recv_buf)) {
        case CONTINUE: break;
        default:   goto exit;
    }
    printf("idx = %d; in_len = %d, payload = '", idx, in_len);
    for (int i=0; i<in_len; i++ ) printf("%c", recv_buf[idx+i]);
    printf("'\n");
    return;
exit:
	printf("idx = %d; in_len = %d, no payload\n", idx, in_len);
	return; 
}

int main(void)
{
	test1();
	test2();
	test3();
}