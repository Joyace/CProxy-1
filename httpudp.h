#ifndef HTTPUDP_H
#define HTTPUDP_H

#include "main.h"

//默认使用HTTPS模块
//#define HTTPUDP_REQUEST "GET / HTTP/1.1\r\nHost: [H]\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ChameleonProxy httpUDP Client\r\nSec-WebSocket-Version: "VERSION"\r\nUpgrade: websocket\r\nProxy-Connection: Keep-Alive\r\n\r\n"

extern void *udp_loop(void *nullPtr);

#endif