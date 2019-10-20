#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "../main/secrets/base64.h"

#define p_green(b, ...) printf("\n\033[1;32m");printf(b, ##__VA_ARGS__);printf("\033[1;0m")
#define p_red(b, ...)   printf("\n\033[1;31m");printf(b, ##__VA_ARGS__);printf("\033[1;0m")

void test1 (void)
{
	static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static const char cs_b64[] = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
	static const int cs_len = 36;
	static const int buf_len = 72;
	static       int b64_len = 72;
	static char out[72];
	static char out2[72];


	int i;
	for (i=0; i<buf_len; i++) out[i]='\0';
	for (i=0; i<buf_len; i++) out2[i]='\0';
	printf("cs %s\n", cs);
	printf("out %s\n", out);
	b64_len = base64((void *)cs, cs_len, out); 
	printf("base64 encoded cs %s, length %d\n", out, b64_len);
	assert(!memcmp(cs_b64,out,b64_len));

	b64_len = unbase64(out, b64_len, (uint8_t *)out);
	printf("base64 decoded encoded cs '%s', length %d\n", out, b64_len);
	for (i=0; i<b64_len; i++) printf ("%c", out[i]); printf("\n");
	assert(!memcmp(cs,out,b64_len));
	//assert(cs_len == strlen(out));

	p_green("test1 base64 encode/decode passed");
}

void test2 (void)
{
    #define cs_len 1101
	static uint8_t cs[cs_len];
	#define buf_len 1500
	static uint8_t out[buf_len];
	static uint8_t out2[buf_len];

	const int k_max = 1000;
	
	int out_b64_len = 0;
	int out2_b64_len = 0;
	int k;
	time_t t;

	srand(time(&t));

	for (k=0; k<k_max; k++) {
		memset(out, 0, buf_len);
		memset(out2, 0, buf_len);

		for (int i=0; i<cs_len; i++) cs[i]=rand();

		out_b64_len = base64((void *)cs, cs_len, out); 
		assert(out_b64_len<buf_len);

		out2_b64_len = unbase64(out, out_b64_len, out);

		assert(!memcmp(cs,out,out2_b64_len));
		assert(cs_len == out2_b64_len);
	}
	p_green("test2 base64 encode/decode passed\n");
}

void main (void)
{
	test1();
	test2();
}