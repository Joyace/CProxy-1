#ifndef CONF_H
#define CONF_H

#include <ctype.h>
#include <arpa/inet.h>
#include "main.h"

extern void read_conf(char *path);

struct modify {
    char *first, *del_hdr, *src, *dest;
    struct modify *next;
    int first_len, del_hdr_len, src_len, dest_len;
    unsigned flag :3; //判断修改请求头的操作
};
struct tcp_conf {
    struct sockaddr_in dst;
    struct modify *m;
};
struct httpudp_conf {
    struct sockaddr_in dst;
    char *http_request;
    int http_request_len;
    int8_t encodeCode;  //数据编码传输
    unsigned httpsRspEncodeCode :1;
};
struct httpdns_conf {
    struct sockaddr_in dst;
    char *http_req, *cachePath, *ssl_request;
    int http_req_len, cacheLimit, ssl_request_len;
    int8_t encodeCode;  //Host编码传输
    unsigned httpRspEncodeCode :1;  //通过HTTP代理，回应头编码
};
struct config {
    //http部分
    struct tcp_conf http;
    //https部分
    struct tcp_conf https;
    //httpdns部分
    struct httpdns_conf dns;
    //httpudp部分
    struct httpudp_conf udp;
    //global部分
    int tcp_listen_fd, dns_listen_fd, udp_listen_fd, uid, procs;
    unsigned mode :3;
    unsigned http_only_get_post :1;
    unsigned strict_modify :1;
};

extern struct config conf;

#endif
