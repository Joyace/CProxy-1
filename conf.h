#ifndef CONF_H
#define CONF_H

#include <regex.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "main.h"

extern void read_conf(char *path);

struct modify {
    char *first, *del_hdr, *src, *dest;
    struct modify *next;
    int first_len, src_len, dest_len;
    unsigned flag :3; //判断修改请求头的操作
};

struct tcp_conf {
    struct sockaddr_in dst;
    struct modify *m;
};

struct httpdns_conf {
    struct sockaddr_in dst;
    char *http_req, *cachePath;
    int http_req_len, cacheLimit;
};

struct config {
    //httpdns部分
    struct httpdns_conf dns;
    //http部分
    struct tcp_conf http;    
    //https部分
    struct tcp_conf https;
    //global部分
    int tcp_listen_fd, dns_listen_fd, uid, procs;
    unsigned mode :3;
    unsigned http_only_get_post :1;
    unsigned strict_modify :1;
};

extern struct config conf;

#endif
