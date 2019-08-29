#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define LEN 16

uint8_t ctoi (char c)
{
	if (c >= '0' && c <= '9') return (uint8_t) (c - '0');
	if (c >= 'A' && c <= 'F') return (uint8_t) (10 + c - 'A');
	if (c >= 'a' && c <= 'f') return (uint8_t) (10 + c - 'a');
	return -1;
}

int main(void) 
{
	static char in[] = "30313233343536373839414243616263";
	static char in2[] = "0123456789ABCabc";
	static uint8_t out[LEN];
	static uint8_t out2[LEN];

	for (int i=0; i<LEN; i++) {
		out[i] = ctoi(in[2*i])*16 + ctoi(in[2*i+1]);
		printf("%x\n", (int) out[i]);
	}


	in2[0] = 0b00110000;
	in2[1] = 0b00000011;

	printf("char 00110000 %c, 00000011 %c\n", in2[0], in2[1]);

	// for (int i=0; i<17-1; i++) {
	// 	in2[i]   = (uint8_t) (in[i]-'0');
	// 	in2[i+1] = (uint8_t) (in[i+1]-'0'); 
	// }
    //for(i = 0; i<len; i++){
    //    sprintf(out+i*2, "%02X", in[i]);


	//for (int i=0; i<strlen(in); i++) printf("%B\n", in[i]);

	// for (int i=0; i<strlen(in); i++) {
	// 	if (in[i] >= 'a' && in[i] <= 'z') then out[i] = unsigned char(in[i] - '0' - 26)
	// 	else if (in[i] >= '0' && in[i] <= 'Z') then out[i] = unsigned char(in[i] - '0');
	// }
	return 0;
}