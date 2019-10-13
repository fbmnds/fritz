#ifndef _TEST_SECRETS_H_
#define _TEST_SECRETS_H_

#define GCC_X86 1
#define TEST 1

static char API_KEY[] = "0000-0000-0000";
static char API_KEY_PREV[] = "____-____-____";

#include "../main/secrets/algos.h"

static unsigned char IV[] = {0xFF,0xEE,0xDD,0xCC,0xBB,0xAA,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};

static esp_aes_context secret_ctx = {
    .key_bytes = AES_KEY_SIZE,
    .key = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}
};

#endif