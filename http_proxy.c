#include <limits.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include "http_proxy.h"

#define TCP_MAX_FD 892  //1024 - tcpListenFd - dnsListenFd - epollFd(2个) - dnsFd(128个)
#define BUFFER_SIZE 4096
#define RESPONSE_SIZE 2048

static conn_t ct_list[TCP_MAX_FD];
static struct epoll_event tcp_evs[TCP_MAX_FD], tcp_ev;
struct ssl_string *ssl_str = NULL;
static struct ssl_string *https_string;
static int tcp_efd;
uint16_t tcp_listen_port;

/* 关闭TCP连接 */
static void close_connection(conn_t *proxyEnd)
{
    epoll_ctl(tcp_efd, EPOLL_CTL_DEL, proxyEnd->fd, NULL);
    close(proxyEnd->fd);
    if ((proxyEnd - ct_list) & 1)
    {
        char *server_data;

        server_data = proxyEnd->ready_data;
        memset(proxyEnd, 0, sizeof(conn_t));
        proxyEnd->ready_data = server_data;
        proxyEnd-- ->fd = -1;
    }
    else
    {
        free(proxyEnd->connect);
        free(proxyEnd->ready_data);
        free(proxyEnd->incomplete_data);
        memset(proxyEnd, 0, sizeof(conn_t));
        proxyEnd++ ->fd = -1;
    }
    if (proxyEnd->fd >= 0)
        close_connection(proxyEnd);
}

/* 读取客户端数据 */
static int8_t read_client(conn_t *client)
{
    char *new_data, *head, *tail;
    int read_len;
    
    do {
        new_data = (char *)realloc(client->incomplete_data, client->incomplete_data_len + BUFFER_SIZE + 1);
        if (new_data == NULL)
            return -1;
        client->incomplete_data = new_data;
        read_len = read(client->fd, client->incomplete_data + client->incomplete_data_len, BUFFER_SIZE);
        /* 判断是否关闭连接 */
        if (read_len <= 0)
        {
            if (read_len == 0 || errno != EAGAIN)
                return -1;
            else if (client->incomplete_data_len == 0)
                return 1;
            return 0;
        }
        client->incomplete_data_len += read_len;
        client->incomplete_data[client->incomplete_data_len] = '\0';
        /* 判断是否读取完所有http请求头 */
        for (head = client->incomplete_data; head - client->incomplete_data <= client->incomplete_data_len; head = tail + 3)
        {
            //不是http请求头，返回
            if (request_type(head) == OTHER)
                return 0;
            tail = strstr(head, "\n\r");
            //如果是NULL，则没有读取完整http请求头
            if (tail == NULL)
            {
                if (read_len < BUFFER_SIZE)
                    return 1;  //已经读完当前客户端的数据，等待下次读取
                else
                    break;  //客户端可能还有数据可读
            }
        }
    } while (1);

    return 0;
}

static int8_t create_connect(conn_t *client, conn_t *server)
{
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0)
        return 1;
    fcntl(server->fd, F_SETFL, O_NONBLOCK);
    tcp_ev.data.ptr = server;
    tcp_ev.events = EPOLLOUT|EPOLLET;
    epoll_ctl(tcp_efd, EPOLL_CTL_ADD, server->fd, &tcp_ev);
    //[不是普通http请求/wap_connect 所有数据]/[net_connect HTTP非80 8080端口]   走https地址
    if (client->reqType == OTHER || 
    client->reqType == HTTP_CONNECT ||
    conf.mode == WAP_CONNECT ||
    (conf.mode == NET_CONNECT && client->original_port != 80 && client->original_port != 8080))
    {
        if (connect(server->fd, (struct sockaddr *)&conf.https.dst, sizeof(addr)) != 0 && errno != EINPROGRESS)
            return 1;
        if (client->reqType != HTTP_CONNECT && make_ssl(client) != 0)
            return 1;
    }
    //[wap HTTP数据]/[net_proxy HTTP非80 8080端口]
    else if (conf.mode == WAP || (conf.mode == NET_PROXY && client->original_port != 80 && client->original_port != 8080))
    {
        if (connect(server->fd, (struct sockaddr *)&conf.http.dst, sizeof(addr)) != 0 && errno != EINPROGRESS)
            return 1;
    }
    //直连目标地址
    else
    {
        if (connect(server->fd, (struct sockaddr *)&client->original_dst, sizeof(addr)) != 0 && errno != EINPROGRESS)
            return 1;
    }
    return 0;
}

/* 处理客户端数据 */
static void handleClient(conn_t *client)
{
    conn_t *server;
    int write_len;

    if (client->fd < 0)
        return;
    //TCP数据先全部发送到服务端再读取
    if (client->ready_data != NULL && client->reqType == OTHER)
        return;
    
    server = client + 1;
    /* 读取客户端数据 */
    switch (read_client(client))
    {
        //没毛病
        case 0:
        break;

        //连接断开
        case -1:
            close_connection(client);
    
        //当前客户端没有数据读取或者是http请求头没有读取完整，等待下次客户端数据
        case 1:
        return;
    }
    /* 修改http请求头 */
    client->reqType = request_type(client->incomplete_data);
    if (modify_request(client->incomplete_data, client->incomplete_data_len, client) != 0)
    {
        client->incomplete_data = NULL;
        close_connection(client);
        return;
    }
    client->incomplete_data = NULL;
    client->incomplete_data_len = 0;
    /* 连接到目标服务器 */
    if (server->fd < 0)
    {
        if (create_connect(client, server) != 0)
            close_connection(client);
        free(client->host);
        return;
    }
    /* 判断是否应用SSL代理 */
    else if (client->first_connection == 1)
    {
        client->first_connection = 0;
        if (client->reqType != OTHER && conf.mode != WAP_CONNECT && !(conf.mode == NET_CONNECT && client->original_port != 80 && client->original_port != 8080))
        {
            for (https_string = ssl_str; https_string && strstr(client->ready_data, https_string->str) == NULL; https_string = https_string->next);
            if (https_string == NULL)
            {
                epoll_ctl(tcp_efd, EPOLL_CTL_DEL, server->fd, NULL);
                close(server->fd);
                if (create_connect(client, server) != 0)
                {
                    close_connection(client);
                    return;
                }
                free(client->connect);
                client->connect = NULL;
                client->connect_len = 0;
                return;
            }
        }
    }
    tcp_ev.data.ptr = server;
    tcp_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
    epoll_ctl(tcp_efd, EPOLL_CTL_MOD, server->fd, &tcp_ev);
}

/* 将服务端的数据转发给客户端 */
static void serverToClient(conn_t *server)
{
    conn_t *client;
    int write_len;

    client = server - 1;
    while ((server->ready_data_len = read(server->fd, server->ready_data, BUFFER_SIZE)) > 0)
    {
        write_len = write(client->fd, server->ready_data, server->ready_data_len);
        if (write_len == -1)
        {
            if (errno != EAGAIN)
                close_connection(server);
            else
                server->sent_len = 0;
            return;
        }
        else if (write_len < server->ready_data_len)
        {
            server->sent_len = write_len;
            tcp_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
            tcp_ev.data.ptr = client;
            epoll_ctl(tcp_efd, EPOLL_CTL_MOD, client->fd, &tcp_ev);
            return;
        }
    }
    //判断客户端是否关闭连接
    if (server->ready_data_len == 0 /*|| errno != EAGAIN*/)
        close_connection(server);
    else
    {
        tcp_ev.data.ptr = server;
        tcp_ev.events = EPOLLIN|EPOLLET;
        epoll_ctl(tcp_efd, EPOLL_CTL_MOD, server->fd, &tcp_ev);
        server->ready_data_len = server->sent_len = 0;
    }
}

static int8_t send_CONNECT(conn_t *client, conn_t *server)
{
    int write_len;
    
    write_len = write(server->fd, client->connect, client->connect_len);
    if (write_len == client->connect_len)
    {
        free(client->connect);
        client->connect = NULL;
        return 0;
    }
    else if (write_len > 0)
    {
        client->connect_len -= write_len;
        memmove(client->connect, client->connect + write_len, client->connect_len);
        return 1;
    }
    else
    {
        if (errno != EAGAIN)
            close_connection(client);
        return 1;
    }
}

/* 数据输出 */
static void data_out(conn_t *to)
{
    conn_t *from;
    int write_len;

    if (to->fd < 0)
        return;

    if ((to - ct_list) & 1)
    {
        from = to - 1;
        to->established = 1;
        if ((from->connect && send_CONNECT(from, to) != 0) || from->ready_data == NULL)
            return;
    }
    else
    {
        from = to + 1;
        if (from->ready_data_len <= 0)
        {
            close_connection(to);
            return;
        }
    }

    write_len = write(to->fd, from->ready_data + from->sent_len, from->ready_data_len - from->sent_len);
    if (write_len == from->ready_data_len - from->sent_len)
    {
        if ((from - ct_list) & 1)
        {
            //服务端可能还有数据未读取
            serverToClient(from);
        }
        else
        {
            free(from->ready_data);
            from->ready_data = NULL;
            from->ready_data_len = from->sent_len = 0;
            tcp_ev.data.ptr = to;
            tcp_ev.events = EPOLLIN|EPOLLET;
            epoll_ctl(tcp_efd, EPOLL_CTL_MOD, to->fd, &tcp_ev);
            //客户端可能还有数据未读取
            handleClient(from);
        }
    }
    else if (write_len > 0)
    {
        from->sent_len += write_len;
    }
    else
    {
        if (errno != EAGAIN)
        {
            close_connection(to);
        }
        else
        {
            tcp_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
            tcp_ev.data.ptr = to;
            epoll_ctl(tcp_efd, EPOLL_CTL_MOD, to->fd, &tcp_ev);
        }
    }
}

/* 数据输入 */
static void data_in(conn_t *in)
{
    if (in->fd < 0)
        return;
    
    /* 处理服务端数据 */
    if ((in - ct_list) & 1)
    {
        in->established = 1;
        conn_t *client = in - 1;
        //CONNECT代理没有接收核心发出的CONNECT回应
        if (client->connect == NULL && client->connect_len > 0)
        {
            client->connect_len = 0;
            if (read(in->fd, in->ready_data, BUFFER_SIZE) <= 0)
            {
                close_connection(in);
                return;
            }
        }
        if (in->ready_data_len == 0)
            serverToClient(in);
    }
    else
        handleClient(in);
}


/* 这个函数单独一个线程处理，接受客户端的TCP连接 */
static void *wait_new_client(void *ptr)
{
    struct epoll_event epoll_ev;
    conn_t *client, *server;
    int fd;
    
    while (1)
    {
        fd = accept(conf.tcp_listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (fd < 0)
            continue;
        for (client = ct_list; client - ct_list < TCP_MAX_FD && client->fd > -1; client += 2);
        if (client - ct_list >= TCP_MAX_FD)
        {
            close(fd);
            continue;
        }
        fcntl(fd, F_SETFL, O_NONBLOCK);
        epoll_ev.data.ptr = client;
        epoll_ev.events = EPOLLIN|EPOLLET;
        epoll_ctl(tcp_efd, EPOLL_CTL_ADD, fd, &epoll_ev);
        client->fd = fd;
        getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &client->original_dst, &addr_len);
        client->original_port = ntohs(client->original_dst.sin_port);
        //读取客户端数据前首先建立连接
        if (client->original_port != 80 && client->original_port != 8080 && client->original_port != tcp_listen_port)
        {
            server = client + 1;
            server->fd = socket(AF_INET, SOCK_STREAM, 0);
            if (server->fd < 0)
            {
                close_connection(client);
                continue;
            }
            fcntl(server->fd, F_SETFL, O_NONBLOCK);
            epoll_ev.data.ptr = server;
            epoll_ev.events = EPOLLOUT|EPOLLET;
            epoll_ctl(tcp_efd, EPOLL_CTL_ADD, server->fd, &epoll_ev);
            if (connect(server->fd, (struct sockaddr *)&conf.https.dst, sizeof(addr)) != 0 && errno != EINPROGRESS)
            {
                close_connection(client);
                continue;
            }
            if (make_ssl(client) != 0)
            {
                close_connection(client);
                continue;
            }
            client->first_connection = 1;
        }
    }
    
    //这句为了消除警告
    return NULL;
}

void tcp_init()
{
    int i;

    tcp_efd = epoll_create(TCP_MAX_FD);
    if (tcp_efd < 0)
    {
        perror("epoll_create");
        exit(1);
    }
    memset(ct_list, 0, sizeof(ct_list));
    for (i = 0; i < TCP_MAX_FD; i++)
        ct_list[i].fd = -1;
    //服务端的结构体分配缓冲空间
    for (i = 1; i < TCP_MAX_FD; i += 2)
    {
        ct_list[i].ready_data = (char *)malloc(BUFFER_SIZE+1);
        if (ct_list[i].ready_data == NULL)
            error("out of memory.");
    }
    //构建模式CONNECT请求
    conn_t ssl;
    memset(&ssl, 0, sizeof(conn_t));
    ssl.reqType = HTTP_CONNECT;
    ssl.host = (char *)1; //不保存Host
    if (modify_request(strdup(CONNECT_HEADER), strlen(CONNECT_HEADER), &ssl) != 0)
        error("out of memory.");
    default_ssl_request = ssl.ready_data;
    default_ssl_request_len = ssl.ready_data_len;
}

void tcp_loop()
{
    pthread_t thread_id;
    int n;
    
    //单独线程accept()在多进程环境下不会惊群
    pthread_create(&thread_id, NULL, wait_new_client, NULL);
    while (1)
    {
        n = epoll_wait(tcp_efd, tcp_evs, TCP_MAX_FD, -1);
        while (n-- > 0)
        {
            if (tcp_evs[n].events & EPOLLIN)
            {
                data_in((conn_t *)tcp_evs[n].data.ptr);
            }
            if (tcp_evs[n].events & EPOLLOUT)
            {
                data_out((conn_t *)tcp_evs[n].data.ptr);
            }
        }
    }
}


int tcp_listen(char *ip, int port)
{
    int fd, optval = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt");
        exit(1);
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("bind");
        exit(1);
    }
    if (listen(fd, 500) != 0)
    {
        perror("listen");
        exit(1);
    }

    tcp_listen_port = port;
    return fd;
}

