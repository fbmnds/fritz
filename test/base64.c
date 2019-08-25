#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "../main/secrets/base64.h"


void test1 (void)
{
	static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static const char cs_b64[] = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
	static const int cs_len = 36;
	static const int buf_len = 72;
	static       int b64_len = 72;
	static char out[] = "'                                                                      '";
	static char out2[] = "                                                                        ";


	int i;
	for (i=0; i<buf_len; i++) out[i]='\0';
	for (i=0; i<buf_len; i++) out2[i]='\0';
	printf("cs %s\n", cs);
	printf("out %s\n", out);
	base64((void *)cs, cs_len, out);
	b64_len = strlen(out); 
	printf("base64 encoded cs %s, length %d\n", out, b64_len);
	unbase64(out, b64_len, (uint8_t *)out2, &b64_len);
	b64_len = strlen(out2); 
	printf("base64 decoded encoded cs '%s', length %d\n", out2, b64_len);
	for (i=0; i<buf_len; i++) printf ("%c", out2[i]);
	printf("\n");

	assert(!memcmp(cs_b64,out,strlen(out)));
	assert(!memcmp(cs,out2,strlen(out2)));
	assert(cs_len == strlen(out2));
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
		int i;
		for (i=0; i<buf_len; i++) out[i]='\0';
		for (i=0; i<buf_len; i++) out2[i]='\0';

		for (i=0; i<cs_len; i++) cs[i]=rand();

		base64((void *)cs, cs_len, out);
		out_b64_len = strlen(out); 
		assert(out_b64_len<buf_len);

		unbase64(out, out_b64_len, out2, &out2_b64_len);

		assert(!memcmp(cs,out2,out2_b64_len));
		assert(cs_len == out2_b64_len);
	}
}

void main (void)
{
	test1();
	test2();
}