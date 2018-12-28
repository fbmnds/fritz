/* OpenSSL server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#ifndef _OPENSSL_SERVER_H_
#define _OPENSSL_SERVER_H_


#define TLS_TASK_NAME        "tls"
#define TLS_TASK_STACK_WORDS 10240
#define TLS_TASK_PRIORITY    5

#define TLS_RECV_BUF_LEN     1024

#define TLS_LOCAL_TCP_PORT   443

#define TLS_SERVER_ACK_1 "HTTP/1.1 200 OK\r\n" \
                         "Connection: close\r\n" \
                         "Content-Type: %s\r\n" \
                         "Content-Length: %d\r\n\r\n" \
                         "%s" \
                         "\r\n"
#define TLS_SERVER_ACK_1_LEN    81
#define TLS_SERVER_ACK_1_BUFLEN 8850


#endif
