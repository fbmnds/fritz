#ifndef _HTTP_STRING_H_
#define _HTTP_STRING_H_

#include <string.h>

static const char upload_url[]  = "POST /upload/";
static const int  upload_url_len = 12; // strlen("POST /upload")


typedef struct str_p {
    char* fn;
    int  len;
} str_pt;

static str_pt fn = {
    .fn  = NULL,
    .len = 0
};

int upload_fn (str_pt* fn, const char* recv_buf, const char* upload_url)
{
    char *ret;
    int idx;

    ret = strstr(recv_buf, upload_url);
    if (ret) {
        fn->fn = ret+upload_url_len*sizeof(char);
        fn->len = 0;
        idx = upload_url_len;
        while (ret[idx] != '\0' &&
               ret[idx] != '\r' &&
               ret[idx] != '\n' &&
               ret[idx] != ' ') {
            idx++;
            fn->len++;
        }
        return 0;
    } else {
        fn = NULL;
        return 1;
    }
}


#endif