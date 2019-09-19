#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define ESP_LOGI(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__)
#define ESP_LOGE(a, b, ...) printf("%s", a); printf(b, ##__VA_ARGS__)

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

#include "../main/http/http_upload.h"






static const char recv_buf[] = "POST /upload/test.txt HTTP/1.1\r\nContent-Length: 123\r\n";
static const char test[] = "test.txt";

void test1(void)
{
	static str_pt fn;
	int ret;

	ret = upload_fn (&fn, recv_buf, upload_url);
	printf("ret %d, fn.len %d, fn.str: '", ret, fn.len);
	for (int i=0; i<fn.len; i++) printf("%c", fn.str[i]);
	printf("'\nstrlen = %ld\n", strlen(test));
	printf("test[9] = %d\n", test[9]);
	printf("recv_buf[strlen] = %d\n", recv_buf[strlen(recv_buf)]);
	printf("recv_buf[strlen++] = %d\n", recv_buf[strlen(recv_buf)+1]);
}


void test2 () {
   char str[80] = "This is - www.tutorialspoint.com - website";
   const char s[2] = "-";
   char *token;
   
   /* get the first token */
   token = strtok(str, s);
   
   /* walk through other tokens */
   while( token != NULL ) {
      printf( " %s\n", token );  
      token = strtok(NULL, s);
   }
   
   return;
}

int main(void)
{
	test1();
	test2();
}