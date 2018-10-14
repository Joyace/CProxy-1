#include <sys/wait.h>
#include <sys/stat.h>
#include "httpdns.h"

#define DNS_MAX_CONCURRENT 128
#define DNS_REQUEST_MAX_SIZE 512
#define HTTP_RSP_SIZE 1024

typedef struct dns_connection {
    char dns_req[DNS_REQUEST_MAX_SIZE];
    struct sockaddr_in src_addr;
    char *reply;  //回应内容
    char *http_request;
    char *host;
    int http_request_len, dns_rsp_len, fd;
    /*
        sent_CONNECT_len:
            在使用SSL代理的情况下，与httpDNS的CONNECT请求长度对比
            小于表示需要发送CONNECT请求，并且还没有发送完成
            等于表示已经完成CONNECT连接
            大于表示已发送完成CONNECT连接，但是没有读取CONNECT的回应包
    */
    int sent_CONNECT_len;
    char query_type;
    unsigned host_len :7;
    unsigned wait_response_client :1;  //等待回应客户端
} dns_t;

static dns_t dns_list[DNS_MAX_CONCURRENT];
static char http_rsp[HTTP_RSP_SIZE+1], *connect_request = NULL;
static struct epoll_event dns_evs[DNS_MAX_CONCURRENT+1], dns_ev;
static int dns_efd;
static int connect_request_len;
/* 缓存变量 */
FILE *cfp = NULL;
static struct dns_cache *cache = NULL;
static struct dns_cache *cache_temp;
static int cache_using;
//子进程先写入缓存，再到父进程写入，否则可能导致缓存文件错乱
pid_t child_pid = 0;

/* 读取缓存文件 */
int8_t read_cache_file()
{
    char *buff, *answer, *question;
    long file_size;

    cache_temp = NULL;
    cache_using = 0;
    if ((cfp = fopen(conf.dns.cachePath, "r+")) == NULL)
    {
        //创建文件并设置权限
        if ((cfp = fopen(conf.dns.cachePath, "w")) != NULL)
        {
            chmod(conf.dns.cachePath, S_IWOTH|S_IROTH|S_IWGRP|S_IRGRP|S_IWUSR|S_IRUSR);
            fclose(cfp);
            return 0;
        }
        return 1;
    }

    //读取文件内容
    fseek(cfp, 0, SEEK_END);
    file_size = ftell(cfp);
    if ((buff = (char *)alloca(file_size)) == NULL)
        return 1;
    rewind(cfp);
    fread(buff, file_size, 1, cfp);
    fclose(cfp);

    //读取缓存，一组缓存的内容为[ipDomain\0]，其中ip占5字节
    for (answer = buff; answer - buff < file_size; answer = question + cache->question_len + 1)
    {
        cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
        if (cache_temp == NULL)
            return 1;
        cache_temp->next = cache;
        cache = cache_temp;
        cache_using++;
        cache->answer = strndup(answer, 4);
        question = answer + 4;
        cache->question = strdup(question);
        if (cache->question == NULL || cache->answer == NULL)
            return 1;
        cache->question_len = strlen(question);
    }
    /* 删除重复记录 */
    struct dns_cache *before, *after;
    for (; cache_temp; cache_temp = cache_temp->next)
    {
        for (before = cache_temp; before && (after = before->next) != NULL; before = before->next)
        {
            if (strcmp(after->question, cache_temp->question) == 0)
            {
                before->next = after->next;
                free(after->question);
                free(after->answer);
                free(after);
                cache_using--;
            }
        }
    }

    chmod(conf.dns.cachePath, S_IWOTH|S_IROTH|S_IWGRP|S_IRGRP|S_IWUSR|S_IRUSR);
    return 0;
}

/* 程序结束时将缓存写入文件 */
void write_dns_cache(int sig)
{
    //子进程先写入缓存
    if (child_pid)
    {
        wait(NULL);
        cfp = fopen(conf.dns.cachePath, "a");
    }
    else
    {
        cfp = fopen(conf.dns.cachePath, "w");
    }
    while (cache)
    {
        fputs(cache->answer, cfp);
        fputs(cache->question, cfp);
        fputc('\0', cfp);
        cache = cache->next;
    }

    exit(0);
}

/* 查询缓存 */
static char *cache_lookup(char *question, dns_t *dns)
{
    struct dns_cache *c;

    for (c = cache; c; c = c->next)
    {
        if (strcmp(c->question, question) == 0)
        {
            dns->host_len = c->question_len;
            dns->query_type = 1;
            return c->answer;
        }
    }

    return NULL;
}

/* 记录缓存 */
static void cache_record(dns_t *dns)
{
    cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
    if (cache_temp == NULL)
        return;
    cache_temp->question = strdup(dns->dns_req + 13);
    if (cache_temp->question == NULL)
    {
        free(cache_temp);
        return;
    }
    cache_temp->next = cache;
    cache = cache_temp;
    cache->question_len = dns->host_len;
    cache->answer = dns->reply;
    if (conf.dns.cacheLimit)
    {
        //到达缓存记录条目限制则释放前一半缓存
        if (cache_using >= conf.dns.cacheLimit)
        {
            struct dns_cache *free_c;
            int i;
            for (i = cache_using = conf.dns.cacheLimit >> 1; i--; cache_temp = cache_temp->next);
            for (free_c = cache_temp->next, cache_temp->next = NULL; free_c; free_c = cache_temp)
            {
                cache_temp = free_c->next;
                free(free_c);
            }
        }
        cache_using++;
    }
}

/* 分析DNS请求 */
int8_t parse_dns_request(char *dns_req, dns_t *dns)
{
    int len;

    dns_req += 13;  //跳到域名部分
    dns->host_len = strlen(dns_req);
    //判断请求类型
    switch ((dns->query_type = *(dns_req + 2 + dns->host_len)))
    {
        case 28:    //查询ipv6地址
            dns->query_type = 1; //httpDNS不支持查询ipv6，所以改成ipv4
            
        case 1:    //查询ipv4地址
            dns->host = strdup(dns_req);
            if (dns->host == NULL)
                return 1;
            for (len = *(--dns_req); dns_req[len+1] != 0; len += dns_req[len])
            {
                //防止数组越界
                if (len > dns->host_len)
                {
                    free(dns->host);
                    return 1;
                }
                dns->host[len++] = '.';
            }
            return 0;
            
        default:
            return 1;
    }
}

/* 回应dns客户端 */
int8_t respond_client(dns_t *dns)
{
    char *p;

    //18: 查询资源的前(12字节)后(6字节)部分
    if (dns->reply)
        dns->dns_rsp_len = 18 + dns->host_len + 16;
    else
        dns->dns_rsp_len = 18 + dns->host_len;
    //判断是否超出缓冲大小
    if (dns->dns_rsp_len > DNS_REQUEST_MAX_SIZE)
    {
        dns->query_type = 0;
        return 1;
    }
    /* 问题数 */
    dns->dns_req[4] = 0;
    dns->dns_req[5] = 1;
    /* 资源记录数 */
    dns->dns_req[6] = 0;
    dns->dns_req[7] = 0;
    /* 授权资源记录数 */
    dns->dns_req[8] = 0;
    dns->dns_req[9] = 0;
    /* 额外资源记录数 */
    dns->dns_req[10] = 0;
    dns->dns_req[11] = 0;
    /* 如果有回应内容(资源记录) */
    if (dns->reply)
    {
        p = dns->dns_req + 18 + dns->host_len;
        /* 资源记录数+1 */
        dns->dns_req[7]++;
        /* 成功标志 */
        dns->dns_req[2] = (char)133;
        dns->dns_req[3] = (char)128;
        /* 指向主机域名 */
        p[0] = (char)192;
        p[1] = 12;
        /* 回应类型 */
        p[2] = 0;
        p[3] = dns->query_type;
        /* 区域类别 */
        p[4] = 0;
        p[5] = 1;
        /* 生存时间 (1 ora) */
        p[6] = 0;
        p[7] = 0;
        p[8] = 14;
        p[9] = 16;
        /* 回应长度 */
        p[10] = 0;
        p[11] = 4;
        strcpy(p+12, dns->reply);
    }
    else
    {
        /* 失败标志 */
        dns->dns_req[2] = (char)129;
        dns->dns_req[3] = (char)130;
    }

    //因为UDP是无连接协议，所以不做返回值判断
     sendto(conf.dns_listen_fd, dns->dns_req, dns->dns_rsp_len, 0, (struct sockaddr *)&dns->src_addr, sizeof(addr));
    dns->query_type = 0;
    return 0;
}

void http_out(dns_t *out)
{
    int write_len;
    
    if (connect_request && out->sent_CONNECT_len < connect_request_len)
    {
        write_len = write(out->fd, connect_request + out->sent_CONNECT_len, connect_request_len - out->sent_CONNECT_len);
        if (write_len == -1)
        {
            free(out->http_request);
            epoll_ctl(dns_efd, EPOLL_CTL_DEL, out->fd, NULL);
            close(out->fd);
            out->query_type = 0;
        }
        out->sent_CONNECT_len += write_len;
        if (out->sent_CONNECT_len == connect_request_len)
        {
            out->sent_CONNECT_len++;  //表示已完全发送CONNECT请求
            dns_ev.events = EPOLLIN|EPOLLET;
            dns_ev.data.ptr = out;
            epoll_ctl(dns_efd, EPOLL_CTL_MOD, out->fd, &dns_ev);
        }
        return;
    }
    
    write_len = write(out->fd, out->http_request, out->http_request_len);
    if (write_len == out->http_request_len)
    {
        free(out->http_request);
        dns_ev.events = EPOLLIN|EPOLLET;
        dns_ev.data.ptr = out;
        epoll_ctl(dns_efd, EPOLL_CTL_MOD, out->fd, &dns_ev);
    }
    else if (write_len > 0)
    {
        out->http_request_len -= write_len;
        memmove(out->http_request, out->http_request + write_len, out->http_request_len);
    }
    else
    {
        free(out->http_request);
        epoll_ctl(dns_efd, EPOLL_CTL_DEL, out->fd, NULL);
        close(out->fd);
        out->query_type = 0;
    }
}

void http_in(dns_t *in)
{
    char *ip_ptr, *p;
    int len, i;
    
    if (connect_request && in->sent_CONNECT_len > connect_request_len)
    {
        in->sent_CONNECT_len--;
        do {
            len = read(in->fd, http_rsp, HTTP_RSP_SIZE);
            if (len < 0 && errno != EAGAIN)
            {
                free(in->http_request);
                epoll_ctl(dns_efd, EPOLL_CTL_DEL, in->fd, NULL);
                close(in->fd);
                in->query_type = 0;
                return;
            }
        } while(len == HTTP_RSP_SIZE);
        dns_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
        dns_ev.data.ptr = in;
        epoll_ctl(dns_efd, EPOLL_CTL_MOD, in->fd, &dns_ev);
        return;
    }
    
    len = read(in->fd, http_rsp, HTTP_RSP_SIZE);
    if (len <= 0)
    {
        in->query_type = 0;
        epoll_ctl(dns_efd, EPOLL_CTL_DEL, in->fd, NULL);
        close(in->fd);
        return;
    }
    http_rsp[len] = '\0';
    //printf("[%s]\n", http_rsp);
    p = strstr(http_rsp, "\n\r");
    if (p)
    {
        //部分代理服务器使用长连接，第二次读取数据才读到域名的IP
        if (p + 3 - http_rsp >= len)
            return;
        p += 3;
    }
    else
        p = http_rsp;
    epoll_ctl(dns_efd, EPOLL_CTL_DEL, in->fd, NULL);
    close(in->fd);
    in->reply = (char *)malloc(5);
    if (in->reply == NULL)
        goto error;
    do {
        if (*p == '\n')
            p++;
        /* 匹配IP */
        if (*p  > 57 || *p < 49)
            continue;
        for (i = 0, ip_ptr = p, p = strchr(ip_ptr, '.'); ; ip_ptr = p + 1, p = strchr(ip_ptr, '.'))
        {
            if (i < 3)
            {
                if (p == NULL)
                    goto error;
                //查找下一行
                if (p - ip_ptr > 3)
                    break;
                in->reply[i++] = atoi(ip_ptr);
            }
            else
            {
                in->reply[3] = atoi(ip_ptr);
                in->reply[4] = 0;
                if (respond_client(in) == 0 && cfp)
                    cache_record(in);
                else
                    free(in->reply);
                return;
            }
        }
    } while ((p = strchr(p, '\n')) != NULL);
    
    error:
    free(in->reply);
    in->reply = NULL;
    respond_client(in);
}

static void new_client()
{
    dns_t *dns;
    int i, len;
    
    for (i = 0; i < DNS_MAX_CONCURRENT; i++)
    {
        if (dns_list[i].query_type == 0)
        {
            dns = &dns_list[i];
            break;
        }
    }
    if (i == DNS_MAX_CONCURRENT)
        return;
    len = recvfrom(conf.dns_listen_fd, dns->dns_req, DNS_REQUEST_MAX_SIZE, 0, (struct sockaddr *)&dns->src_addr, &addr_len);
    //dns请求必须大于18
    if (len <= 18)
        return;
    dns->dns_req[len] = '\0';
    /* 查询缓存 */
    if (cfp)
    {
        dns->reply = cache_lookup(dns->dns_req + 13, dns);
        if (dns->reply != NULL)
        {
            respond_client(dns);
            return;
        }
    }
    if (parse_dns_request(dns->dns_req, dns) != 0)
    {
        dns->reply = NULL;
        respond_client(dns);
        return;
    }
    dns->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (dns->fd < 0)
    {
        free(dns->host);
        dns->query_type = 0;
        return;
    }
    fcntl(dns->fd, F_SETFL, O_NONBLOCK);
    dns_ev.events = EPOLLERR|EPOLLOUT|EPOLLET;
    dns_ev.data.ptr = dns;
    if (epoll_ctl(dns_efd, EPOLL_CTL_ADD, dns->fd, &dns_ev) != 0)
    {
        close(dns->fd);
        free(dns->host);
        free(dns->http_request);
        dns->query_type = 0;
        return;
    }
    if (connect(dns->fd, (struct sockaddr *)&conf.dns.dst, sizeof(conf.dns.dst)) != 0 && errno != EINPROGRESS)
    {
        epoll_ctl(dns_efd, EPOLL_CTL_DEL, dns->fd, NULL);
        close(dns->fd);
        free(dns->host);
        dns->query_type = 0;
        return;
    }
    dns->http_request_len = conf.dns.http_req_len;
    dns->http_request = replace(strdup(conf.dns.http_req), &dns->http_request_len, "[D]", 3, dns->host, dns->host_len);
    free(dns->host);
    if (dns->http_request == NULL)
    {
        close(dns->fd);
        dns->query_type = 0;
        return;
    }
    dns->sent_CONNECT_len = 0;
}

void dns_init()
{
    char dest[22], *ip;
    uint16_t port;
    
    port = ntohs(conf.dns.dst.sin_port);
    ip = inet_ntoa(conf.dns.dst.sin_addr);
    sprintf(dest, "%s:%u", ip, port);
    if (conf.dns.http_req == NULL)
    {
        conn_t http;

        memset(&http, 0, sizeof(conn_t));
        http.reqType = HTTP;
        http.host = (char *)1;  //如果为NULL，modify_request函数可能会使其指向动态分配内存
        if (modify_request(strdup(HTTPDNS_REQUEST), strlen(HTTPDNS_REQUEST), &http) != 0)
            exit(1);
        conf.dns.http_req = replace(http.ready_data, &http.ready_data_len, "[H]", 3, dest, strlen(dest));
        conf.dns.http_req_len = http.ready_data_len;
        if (conf.mode == WAP || (conf.mode == NET_PROXY && port != 80 && port != 8080))
            memcpy(&conf.dns.dst, &conf.http.dst, sizeof(conf.dns.dst));
    }
    else
    {
        conf.dns.http_req_len = strlen(conf.dns.http_req);
        //如果不是\r\n\r\n结尾但又是\r\n结尾，自动补上\r\n
        if (strstr(conf.dns.http_req, "\n\r") == NULL && conf.dns.http_req[strlen(conf.dns.http_req) - 1] == '\n')
        {
            conf.dns.http_req_len += 2;
            conf.dns.http_req = (char *)realloc(conf.dns.http_req, conf.dns.http_req_len + 1);
            if (conf.dns.http_req == NULL)
                error("out of memory.");
            strcat(conf.dns.http_req, "\r\n");
        }
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "[M]", 3, "GET", 3);
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "[url]", 5, "/d?dn=[D]", 9);
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "[U]", 3, "/d?dn=[D]", 9);
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "[V]", 3, "HTTP/1.0", 8);
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "[H]", 3, dest, strlen(dest));
        conf.dns.http_req = replace(conf.dns.http_req, &conf.dns.http_req_len, "\\0", 2, "\0", 1);
    }
    if (conf.dns.http_req == NULL)
        error("out of memory.");
    /* 构建CONNECT请求头 */
    if (conf.mode == WAP_CONNECT || (conf.mode == NET_CONNECT && port != 80 && port != 8080))
    {
        conn_t ssl;

        ssl.host = NULL;
        ssl.original_port = port;
        ssl.original_dst.sin_addr.s_addr = inet_addr(ip);
        if (make_ssl(&ssl) != 0)
            error("out of memory.");        
        connect_request = ssl.connect;
        connect_request_len = ssl.connect_len;
        memcpy(&conf.dns.dst, &conf.https.dst, sizeof(conf.dns.dst));
    }
    
    dns_efd = epoll_create(DNS_MAX_CONCURRENT+1);
    if (dns_efd < 0)
    {
        perror("epoll_create");
        exit(1);
    }
    fcntl(conf.dns_listen_fd, F_SETFL, O_NONBLOCK);
    dns_ev.data.fd = conf.dns_listen_fd;
    dns_ev.events = EPOLLIN;
    epoll_ctl(dns_efd, EPOLL_CTL_ADD, conf.dns_listen_fd, &dns_ev);
    memset(dns_list, 0, sizeof(dns_list));
    //程序关闭时写入dns缓存
    signal(SIGTERM, write_dns_cache);
    signal(SIGHUP, write_dns_cache);
    signal(SIGINT, write_dns_cache);
    signal(SIGABRT, write_dns_cache);
    signal(SIGILL, write_dns_cache);
    signal(SIGSEGV, write_dns_cache);
}

void *dns_loop()
{
    int n;

    while (1)
    {
        n = epoll_wait(dns_efd, dns_evs, DNS_MAX_CONCURRENT + 1, -1);
        while (n-- > 0)
        {
            if (dns_evs[n].data.fd == conf.dns_listen_fd)
            {
                new_client();
            }
            else
            {
                if (dns_evs[n].events & EPOLLIN)
                {
                    http_in((dns_t *)dns_evs[n].data.ptr);
                }
                if (dns_evs[n].events & EPOLLOUT)
                {
                    http_out((dns_t *)dns_evs[n].data.ptr);
                }
            }
        }
    }
    
    return NULL;  //消除编译警告
}

int udp_listen(char *ip, int port)
{
    int fd;
    
    if ((fd=socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("udp socket");
        exit(1);
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("udp bind");
        exit(1);
    }

    return fd;
}
