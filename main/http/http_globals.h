#ifndef _HTTP_GLOBALS_H_
#define _HTTP_GLOBALS_H_


#define REGISTER_LEN      64
#define REGISTER_ITEM_LEN 14
#define REGISTER_ITEM_POS 0

#define HTTP_TASK_NAME        "[HTTP]"
#define HTTP_TASK_STACK_WORDS 10240
#define HTTP_TASK_PRIORITY    5

#define HTTP_RECV_MIN_LEN            32
#define HTTP_RECV_BUF_LEN       16*1024
#define HTTP_RECV_BUF_SHORT_LEN    1024
#define HTTP_LOCAL_TCP_PORT          80

#define HTTP_SERVER_ACK \
"HTTP/1.1 200 OK\r\n" \
"Content-Type: text/plain\r\n" \
"Content-Length: 2\r\n\r\n" \
"{}" \
"\r\n"

#define HTTP_SERVER_ACK_LEN strlen(HTTP_SERVER_ACK)

#define HTTP_SERVER_ACK_500 \
"HTTP/1.1 500 OK\r\n" \
"Content-Type: text/plain\r\n" \
"Content-Length: 2\r\n\r\n" \
"{}" \
"\r\n"

#define HTTP_SERVER_ACK_LEN_500 strlen(HTTP_SERVER_ACK_500)


#define HTTP_SERVER_ACK_1 \
"HTTP/1.1 200 OK\r\n" \
"Content-Type: %s\r\n" \
"Content-Length: %d\r\n\r\n" \
"%s" \
"\r\n"

#define HTTP_SERVER_ACK_1_LEN    81
#define HTTP_SERVER_ACK_1_BUFLEN 8850
#define HTTP_SERVER_ACK_1_STATE "{ \"fun_p64\": %d, \"zen\": %d, \"store\": %d, \"eth\": %d }"
#define HTTP_SERVER_ACK_1_STATELEN 48

static bool connected = false;
static char ip[] = "___.___.___.___";
static bool renew_api_key = false;

static const char *TAG = HTTP_TASK_NAME;

#define PIN_1 GPIO_NUM_11 // GPIO_NUM_12
#define PIN_2 GPIO_NUM_14  
#define PIN_3 GPIO_NUM_27
#define PIN_4 GPIO_NUM_26

// in use for SD:
// gpio_set_pull_mode(15, GPIO_PULLUP_ONLY);   // CMD, needed in 4- and 1- line modes
// gpio_set_pull_mode(2, GPIO_PULLUP_ONLY);    // D0, needed in 4- and 1-line modes
// gpio_set_pull_mode(4, GPIO_PULLUP_ONLY);    // D1, needed in 4-line mode only
// gpio_set_pull_mode(12, GPIO_PULLUP_ONLY);   // D2, needed in 4-line mode only
// gpio_set_pull_mode(13, GPIO_PULLUP_ONLY);   // D3, needed in 4- and 1-line modes


static const char rt_post_upload_str[] = "POST /upload/";
static const char rt_post_set_str[]    = "POST /set/";
static const char rt_post_status_str[] = "POST /status";
str_pt rt_post_upload = { .str = (char *)rt_post_upload_str, .len = 13 };
str_pt rt_post_set    = { .str = (char *)rt_post_upload_str, .len = 10 };
str_pt rt_post_status = { .str = (char *)rt_post_status_str, .len = 12 };


typedef enum {
	_200,
	_500,
	DONE,
	CONTINUE
} http_server_label_t;


static const char text_html[] = "text/html";
static const char app_json[]  = "text/plain";

typedef struct pin_state {
    int fun_p64;
    int zen;
    int store;
    int eth;
} pin_state_t;

static pin_state_t pin_state = {
    .fun_p64 = 0,
    .zen     = 0,
    .store   = 0,
    .eth     = 0
};

int cmp_str_head(const char* recv_buf, const str_pt* route)
{
	for (int i=0; i<route->len; i++) {
		if (recv_buf[i] != route->str[i]) return 0;
	}
	return 1;
}

void cp_str_head(char* recv_buf, const str_pt* str)
{
	for (int i=0; i<str->len; i++) recv_buf[i] = str->str[i];
	return;
}

int validate_req(char* recv_buf, const unsigned char* recv_buf_decr)
{
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;x;on
    //     4    9    14   19   24   29
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;x;off
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;
    int i = 0;

    while (recv_buf_decr[i]) {
        recv_buf[i] = (char) recv_buf_decr[i];
        i++;
    }
    recv_buf[i] = '\0';
    if (i < 30) return -1*i;
    if (recv_buf[4] != '-') return -4;
    if (recv_buf[9] != '-') return -9;
    if (recv_buf[14] != ';') return -14;
    if (recv_buf[19] != '-') return -19;
    if (recv_buf[24] != '-') return -24;

    //if (recv_buf[29] != ';') return -29;
    return i;
}

int validate_req_base(str_pt* str, str_pt* key)
{
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;x;on
    //     4    9    14   19   24   29
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx;x;off
    // xxxx-xxxx-xxxx;xxxx-xxxx-xxxx
    if (str->len < 30) return -1;
    if (str->str[4] != '-') return -4;
    if (str->str[9] != '-') return -9;
    if (str->str[19] != '-') return -19;
    if (str->str[24] != '-') return -24;
    if (str->str[14] != ';') return -14;
    //if (str->str[29] != ';') return -29;
    if (!cmp_str_head(&str->str[15], key)) return -15;
    return 0;
}


int register_req(char* req_register, int *register_idx, str_pt* str)
{
    int pos;
    //unsigned char out[32];
    char* curr_item;

    if (API_KEY_LEN != REGISTER_ITEM_LEN) {
        ESP_LOGE(TAG, " register_req system error: API_KEY_LEN != REGISTER_ITEM_LEN");
        return -1;
    }

    //for (int i=0; i< REGISTER_ITEM_LEN; i++) item[i] = (unsigned char) str->str[i];

    ESP_LOGI(TAG, " register_req: item %s", str->str);
    //esp_sha(SHA2_256, (unsigned char*) str->str, 2*REGISTER_ITEM_LEN, (unsigned char *) out);
    //ESP_LOGI(TAG, "register_req hash %s", out);

    // reject API_KEY as invalid register item
    pos = REGISTER_ITEM_LEN;
    for (int i=0; i<REGISTER_ITEM_LEN; i++) {
        if (str->str[i] == API_KEY[i]) pos--;
    }
    if (pos == 0) return 1;

    if (*register_idx == 0) {
    	for (int i=0; i<REGISTER_ITEM_LEN; i++) req_register[i]=str->str[i];
    	*register_idx = 1;
    	return 0;
    }

    for (pos=0; pos<=*register_idx; pos++) {
        curr_item = &req_register[pos*REGISTER_ITEM_LEN];
        // ignore replayed requests
        if (cmp_str_head(curr_item, str) == 1) {
        	ESP_LOGI(TAG, " register_req: pos %d", pos);
        	return 1;
        }
    }        

    ESP_LOGI(TAG, " register_req: *register_idx %d", *register_idx);

    if (*register_idx == REGISTER_LEN) {
        ESP_LOGI(TAG, " register_req: refresh exhausted register");
        memset(req_register, 0, REGISTER_ITEM_LEN*REGISTER_LEN);
        for (int i=0; i<REGISTER_ITEM_LEN; i++) req_register[i] = str->str[i];
        (*register_idx) = 1;
        renew_api_key = true;
        ESP_LOGI(TAG, " register_req: *register_idx %d", *register_idx);
        return 0;
    } 

    ESP_LOGI(TAG, " register_req: register new request");
    for (int i=0; i<REGISTER_ITEM_LEN; i++) {
    	req_register[*register_idx*REGISTER_ITEM_LEN+i] = str->str[i];
    	printf("%c", req_register[*register_idx*REGISTER_ITEM_LEN+i]);
    }
    req_register[*register_idx*(REGISTER_ITEM_LEN*2)] = '\0';
    *register_idx += 1;
    printf("\n");
    //req_register[*register_idx] = hash;
    return 0;
}


http_server_label_t set_payload_idx (int *idx, int *in_len, char* recv_buf)
{
	*in_len = 0;
    *idx = HTTP_RECV_BUF_LEN;

    while (--*idx) {
        if (recv_buf[*idx] == '\r' || recv_buf[*idx] == '\n') recv_buf[*idx] = '\0';
        if (recv_buf[*idx] != '\0' && recv_buf[*idx] != '\r' && recv_buf[*idx] != '\n') break;
    }
    while (*idx) {
        if ((recv_buf[*idx] >= '0' && recv_buf[*idx] <= '9') || 
            (recv_buf[*idx] >= 'a' && recv_buf[*idx] <= 'f')) {
            (*idx)--; 
            (*in_len)++;
        } else 
            break;
    }
    if (*in_len) (*idx)++;
    if (!(*idx)) {
        ESP_LOGE(TAG, "HTTP read: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);        
        return DONE;
    }
    return CONTINUE;
}

http_server_label_t set_payload_idx2 (str_pt* str, char* recv_buf)
{
	str->len = 0;
    str->str = recv_buf + sizeof(char)*HTTP_RECV_BUF_LEN;

    while (--(str->str) != recv_buf) {
        //if (str->str[0] == '\r' || str->str[0] == '\n') str->str[0] = '\0';
        if (str->str[0] != '\0' && str->str[0] != '\r' && str->str[0] != '\n') break;
    }
    //printf("%s", str->str);
    while (str->str != recv_buf) {
    	//printf("%s", str->str);
        if ((str->str[0] >= '0' && str->str[0] <= '9') || 
            (str->str[0] >= 'a' && str->str[0] <= 'f')) {
            (str->str)--; 
            (str->len)++;
        } else 
            break;
    }
    //printf("%d\n", str->len);
    if (str->len) (str->str)++;
    if (str->str == recv_buf) {
        ESP_LOGE(TAG, "HTTP read: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);        
        return DONE;
    }
    return CONTINUE;
}

http_server_label_t set_payload_idx3 (str_pt* str, char* recv_buf)
{
    str->len = 0;
    str->str = recv_buf + sizeof(char)*HTTP_RECV_BUF_LEN;

    while (--(str->str) != recv_buf) {
        //if (str->str[0] == '\r' || str->str[0] == '\n') str->str[0] = '\0';
        if (str->str[0] != '\0' && str->str[0] != '\r' && str->str[0] != '\n') break;
    }
    //printf("%s", str->str);
    while (str->str != recv_buf) {
        //printf("%s", str->str);
        if ((str->str[0] >= '0' && str->str[0] <= '9') || 
            (str->str[0] >= 'a' && str->str[0] <= 'f') ||
            (str->str[0] >= 'A' && str->str[0] <= 'Z') ||
            str->str[0] == '+' || str->str[0] == '/') {
            (str->str)--; 
            (str->len)++;
        } else 
            break;
    }
    //printf("%d\n", str->len);
    if (str->len) (str->str)++;
    if (str->str == recv_buf) {
        ESP_LOGE(TAG, "HTTP read: ignore request");
        ESP_LOGE(TAG, "%s", recv_buf);        
        return DONE;
    }
    return CONTINUE;
}

#endif