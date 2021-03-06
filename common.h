#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include "main.h"

#define VERSION "1.7" //"beta" " " __DATE__ " " __TIME__

extern char *replace(char *str, int *str_len, const char *src, const int src_len, const char *dest, const int dest_len);
extern void error(const char *msg);
extern int udp_listen(char *ip, int port);
extern void dataEncode(char *data, int data_len, int8_t code);

extern struct sockaddr_in addr;
extern socklen_t addr_len;

#endif
