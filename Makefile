OBJ := CProxy
CC := gcc
#如果是安卓编译
ifeq ($(ANDROID_DATA),/data)
	CFLAGS := -O2 -pie
	SHELL := /system/bin/sh
else
	CFLAGS := -O2 -pthread -Wall
endif

all : main.o conf.o http_proxy.o http_request.o common.o httpdns.o common.o httpudp.o
	$(CC) $(CFLAGS) $(DEFS) -o $(OBJ) $^
	strip $(OBJ)
	-chmod 777 $(OBJ) 2>&-

.c.o : 
	$(CC) $(CFLAGS) $(DEFS) -c $<

clean : 
	rm -f *.o
