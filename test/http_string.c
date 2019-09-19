#include <stdio.h>
#include <assert.h>

#include "../main/http/http_string.h"

static const char recv_buf[] = "POST /upload/test.txt HTTP/1.1\r\nContent-Length: 123\r\n";

void test1(void)
{
	static str_pt fn;
	int ret;

	ret = upload_fn (&fn, recv_buf, upload_url);
	printf("ret %d, fn.len %d, fn.fn: '", ret, fn.len);
	for (int i=0; i<fn.len; i++) printf("%c", fn.fn[i]);
	printf("'\n");
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