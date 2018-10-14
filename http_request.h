#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include "main.h"

/* 请求头修改操作 */
#define SET_FIRST 1
#define DEL_HDR 2
#define REGREP 3
#define STRREP 4

extern int8_t modify_request();
extern char *splice_ip_port(char *ip, uint16_t port);

struct http_request {
    int other_len, header_len;
    char *header, *other, *method, *url, *uri, *host, version[8];
};

extern int  default_ssl_request_len;
extern char * default_ssl_request;

#endif