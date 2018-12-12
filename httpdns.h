#ifndef HTTPDNS_H
#define HTTPDNS_H

#include "main.h"

#define HTTPDNS_REQUEST "GET /d?dn=[D] HTTP/1.0\r\nHost: [H]\r\n\r\n"

struct dns_cache {
    char *question;
    char *answer;
    struct dns_cache *next;
    unsigned int question_len;
};

extern void *dns_loop(void *nullPtr);
extern int8_t read_cache_file();
extern int udp_listen(char *ip, int port);

extern pid_t child_pid;
extern FILE *cfp;

#endif
