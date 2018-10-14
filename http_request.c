#include "http_request.h"

char * default_ssl_request;
int  default_ssl_request_len;

/* 判断请求类型 */
uint8_t request_type(char *req)
{
    if (strncmp(req, "GET", 3) == 0 || strncmp(req, "POST", 4) == 0)
        return HTTP;
    else if (strncmp(req, "CONNECT", 7) == 0)
        return HTTP_CONNECT;
    else if (strncmp(req, "HEAD", 4) == 0 ||
    strncmp(req, "PUT", 3) == 0 ||
    strncmp(req, "OPTIONS", 7) == 0 ||
    strncmp(req, "MOVE", 4) == 0 ||
    strncmp(req, "COPY", 4) == 0 ||
    strncmp(req, "TRACE", 5) == 0 ||
    strncmp(req, "DELETE", 6) == 0 ||
    strncmp(req, "LINK", 4) == 0 ||
    strncmp(req, "UNLINK", 6) == 0 ||
    strncmp(req, "PATCH", 5) == 0 ||
    strncmp(req, "WRAPPED", 7) == 0)
        return HTTP_OTHERS;
    else
        return OTHER;
}

/* 返回状态信息 */
void rsp_stats_msg(conn_t *client, char *host)
{
    #define STATUS_REQUEST "HTTP/1.0 200 OK\r\n"\
        "Content-Type: text/plain; charset=utf-8\r\n"\
        "\r\n"\
        "ChameleonProxy(" VERSION ") is running\r\n\r\n"\
        "HTTP:\r\n[HTTP]\r\nHTTPS:\r\n[HTTPS]"
    conn_t https;
    char *rsp_msg;
    int rsp_msg_len;
    
    https.original_port = tcp_listen_port;
    https.host = host;
    if (make_ssl(&https) != 0)
        return;
    rsp_msg_len = strlen(STATUS_REQUEST);
    rsp_msg = replace(strdup(STATUS_REQUEST), &rsp_msg_len, "[HTTP]", 6, client->ready_data, client->ready_data_len);
    rsp_msg = replace(rsp_msg, &rsp_msg_len, "[HTTPS]", 7, https.connect, https.connect_len);
    if (rsp_msg)
    {
        write(client->fd, rsp_msg, rsp_msg_len);
        free(rsp_msg);
    }
    free(https.connect);
}

/* 构建CONNECT请求头 */
int8_t make_ssl(conn_t *ssl)
{
    char *p;
    
    if (ssl->original_port == tcp_listen_port && ssl->host)
    {
        if (strchr(ssl->host, ':') == NULL)
        {
            p = (char *)realloc(ssl->host, strlen(ssl->host) + 4);
            if (p == NULL)
            {
                free(ssl->host);
                return 1;
            }
            ssl->host = p;
            strcat(p, ":80");
        }
        p = ssl->host;
    }
    else
    {
        p = splice_ip_port(inet_ntoa(ssl->original_dst.sin_addr), ssl->original_port);
    }
    ssl->connect = (char *)malloc(default_ssl_request_len + 1);
    if (ssl->connect == NULL)
        return 1;
    //memcpy(ssl->connect, default_ssl_request, default_ssl_request_len + 1);
    strcpy(ssl->connect, default_ssl_request);
    ssl->connect_len = default_ssl_request_len;
    ssl->connect = replace(ssl->connect, &ssl->connect_len, "[H]", 3, p, strlen(p));
    if (ssl->connect == NULL)
        return 1;

    return 0;
}

/* 将ip和端口用:拼接 */
char *splice_ip_port(char *ip, uint16_t port)
{
    static char original_ip_port[22];
    char *p;
    uint8_t a_unit, ip_len;
    
    strcpy(original_ip_port, ip);
    ip_len = strlen(ip);
    original_ip_port[ip_len] = ':';
    p = original_ip_port + ip_len + 6;
    *p = '\0';
    for (a_unit = port % 10; port > 0; port /= 10, a_unit = port % 10)
        *(--p) = a_unit + 48;
    strcpy(original_ip_port + ip_len + 1, p);
    
    return original_ip_port;
}

/* 释放http_request结构体占用的内存 */
void free_http_request(struct http_request *http_req)
{
    free(http_req->header);
    free(http_req->other);
    free(http_req->method);
    if (http_req->url != http_req->uri)
        free(http_req->uri);
    free(http_req->url);
    free(http_req->host);
}

/* 关键字替换 */
char *keywords_replace(char *str, int *str_len, unsigned reqType, struct http_request *http_req)
{
    if (str == NULL)
        return NULL;
    if (reqType != HTTP_CONNECT)
    {
        str = replace(str, str_len, "[M]", 3, http_req->method, strlen(http_req->method));
        str = replace(str, str_len, "[U]", 3, http_req->uri, strlen(http_req->uri));
        str = replace(str, str_len, "[url]", 5, http_req->url, strlen(http_req->url));
        str = replace(str, str_len, "[V]", 3, http_req->version, 8);
    }
    str = replace(str, str_len, "[H]", 3, http_req->host, strlen(http_req->host));
    
    return str;
}


/* 正则表达式字符串替换，str为可用free释放的指针 */
static char *regrep(char *str, int *str_len, const char *src, char *dest, int dest_len)
{
    if (!str || !src || !dest)
        return NULL;

    regmatch_t pm[10];
    regex_t reg;
    char child_num[2] = {'\\', '0'}, *p, *real_dest;
    int match_len, real_dest_len, i;

    p = str;
    regcomp(&reg, src, REG_NEWLINE|REG_ICASE|REG_EXTENDED);
    while (regexec(&reg, p, 10, pm, 0) == 0)
    {
        real_dest = (char *)malloc(dest_len);
        if (real_dest == NULL)
        {
            regfree(&reg);
            free(str);
            return NULL;
        }
        memcpy(real_dest, dest, dest_len);
        real_dest_len = dest_len;
        //不进行不必要的字符串操作
        if (pm[1].rm_so >= 0)
        {
            /* 替换目标字符串中的子表达式 */
            for (i = 1; i < 10 && pm[i].rm_so > -1; i++)
            {
                child_num[1] = i + 48;
                real_dest = replace(real_dest, &real_dest_len, child_num, 2, p + pm[i].rm_so, pm[i].rm_eo - pm[i].rm_so);
                if (real_dest == NULL)
                {
                    regfree(&reg);
                    free(str);
                    return NULL;
                }
            }
        }
        
        match_len = pm[0].rm_eo - pm[0].rm_so;
        p += pm[0].rm_so;
        //目标字符串不大于匹配字符串则不用分配新内存
        if (match_len >= real_dest_len)
        {
            memcpy(p, real_dest, real_dest_len);
            if (match_len > real_dest_len)
                strcpy(p + real_dest_len, p + match_len);
            p += real_dest_len;
            *str_len -= match_len - real_dest_len;
        }
        else
        {
            int diff;
            char *before_end, *new_str;

            diff = real_dest_len - match_len;
            *str_len += diff;
            new_str = (char *)realloc(str, *str_len + 1);
            if (new_str == NULL)
            {
                free(str);
                free(real_dest);
                regfree(&reg);
                return NULL;
            }
            str = new_str;
            before_end = str + pm[0].rm_so;
            p = before_end + real_dest_len;
            memmove(p, p - diff, *str_len - (p - str) + 1);
            memcpy(before_end, real_dest, real_dest_len);
        }
        free(real_dest);
    }

    regfree(&reg);
    return str;
}

/* 在请求头中获取host */
static char *get_host(char *header)
{
    char *key, *host, *key_end, *host_end;
    unsigned int key_len;
    
    host = NULL;
    for (key = strchr(header, '\n'); key++; key = strchr(key_end, '\n'))
    {
        key_end = strchr(key, ':');
        if (key_end == NULL)
            break;
        //部分请求头一行开头为:
        key_len = key_end - key;
        if (key_len <= 0)
            continue;
        if (strncasecmp(key, "x-online-host", key_len) == 0)
        {
            host = key_end + 1;
            break;
        }
        else if (strncasecmp(key, "host", key_len) == 0)
        {
            host = key_end + 1;
        }
    }
    if (host == NULL)
        return NULL;
    while (*host == ' ')
        host++;
    host_end = strchr(host, '\r');
    if (host_end)
        return strndup(host, host_end - host);
    else
        return strdup(host);
}

/* 删除请求头中的头域，并更新header_len的值 */
static void del_hdr(char *header, int *header_len, struct modify *head)
{
    struct modify *m;
    char *key_end, *line_begin, *line_end;
    unsigned int key_len;
    
    for (line_begin = memchr(header, '\n', *header_len); line_begin; line_begin = line_end)
    {
            key_end = strchr(++line_begin, ':');
            if (key_end == NULL)
                return;
            key_len = key_end - line_begin;
            line_end = memchr(key_end, '\n', *header_len - (key_end - header));
            m = head;
            do {
                if (strncasecmp(line_begin, m->del_hdr, key_len) == 0)
                {
                    if (line_end)
                    {
                        //strcpy(line_begin, line_end + 1);
                        memmove(line_begin, line_end + 1, *header_len - ((line_end+1)-header));
                        *header_len -= line_end - line_begin + 1;
                        //新行前一个字符
                        line_end = line_begin - 1;
                    }
                    else
                    {
                        *header_len = line_begin - header;
                        *line_begin = '\0';
                    }
                    break;
                }
            } while ((m = m->next) != NULL && m->flag == DEL_HDR);
    }
}

/* 处理CONNECT请求头 */
int8_t CONNECT_request_header(char *request, int request_len, struct http_request *http_req)
{
    char *url_end; //pb0指向请求方法后的空格，pb1指向http版本后的空格

    url_end = strchr(request + 8, ' ');
    if (url_end == NULL)
        return 1;
    http_req->host = strndup(request + 8, url_end - (request + 8));
    if (http_req->host == NULL)
        return 1;
    http_req->header = request;
    http_req->header_len = request_len;

    return 0;
}

/* 处理http请求头 */
static int8_t http_request_header(char *request, int request_len, conn_t *client, struct http_request *http_req)
{
    char *p;

    /* 分离请求头和请求数据 */
    http_req->header = request;
    if ((p = strstr(request, "\n\r")) != NULL && (http_req->header_len = p + 3 - request) < request_len)
    {
        http_req->other_len = request_len - http_req->header_len;
        http_req->other = (char *)malloc(http_req->other_len);
        if (http_req->other)
            memmove(http_req->other, p + 3, http_req->other_len);
        else
            return 1;
        *(http_req->header + http_req->header_len) = '\0';
    }
    else
    {
        http_req->header_len = request_len;
    }

    /*获取method url version*/
    p = strchr(http_req->header, ' ');
    if (p)
    {
        http_req->method = strndup(http_req->header, p - http_req->header);
        char *cr = strchr(++p, '\r'); //http版本后的\r
        if (cr)
        {
            http_req->url = strndup(p, cr - p - 9);
            memcpy(http_req->version ,cr - 8, 8);
        }
    }

    http_req->host = get_host(http_req->header);
     //如果请求头中没有Host，则设置为原始IP和端口
    if (http_req->host == NULL)
        http_req->host = strdup(splice_ip_port(inet_ntoa(client->original_dst.sin_addr), client->original_port));

    if (http_req->url)
    {
        if (*http_req->url != '/' && (p = strstr(http_req->url, "//")) != NULL)
        {
            p = strchr(p+2, '/');
            if (p)
                http_req->uri = strdup(p);
            else
                http_req->uri = strdup("/");
        }
        else
            http_req->uri = http_req->url;
    }

    return 0;
}

/*
    修改请求头
   返回值: -1为错误，0为需要代理的请求，1为不需要代理的请求
 */
int8_t modify_request(char *request, int request_len, conn_t *client)
{
    struct http_request http_req;
    struct modify *mod;
    char *p, *new_header, *first, *src, *dest;
    int first_len, src_len, dest_len;

    //判断数据类型
    switch(client->reqType)
    {
        case HTTP_OTHERS:
            if (conf.http_only_get_post)
            {
                free(request);
                return 1;
            }
            //不禁止其他http请求则进行http处理

        case HTTP:
            mod = conf.http.m;
            memset((struct http_request *)&http_req, 0, sizeof(http_req));
            if (http_request_header(request, request_len, client, &http_req) != 0)
            {
                free(request);
                return -1;
            }
            break;

        case HTTP_CONNECT:
            mod = conf.https.m;
            memset((struct http_request *)&http_req, 0, sizeof(http_req));
            if (CONNECT_request_header(request, request_len, &http_req) != 0)
            {
                free(request);
                return -1;
            }
            break;

        //不是http请求头，直接拼接到client->ready_data
        default:
            if (client->ready_data)
            {
                p = (char *)realloc(client->ready_data, client->ready_data_len + request_len + 1);
                if (p == NULL)
                {
                    free(request);
                    return -1;
                }
                client->ready_data = p;
                memcpy(p + client->ready_data_len, request, request_len);
                client->ready_data_len += request_len;
                free(request);
            }
            else
            {
                client->ready_data = request;
                client->ready_data_len = request_len;
            }
        return 0;
    }

    while (mod)
    {
        switch (mod->flag)
        {
            case DEL_HDR:
                del_hdr(http_req.header, &http_req.header_len, mod);
                //del_hdr函数连续删除头域一次性操作
                while (mod->next && mod->next->flag == DEL_HDR)
                    mod = mod->next;
            break;
            
            case SET_FIRST:
                first_len = mod->first_len;
                first = keywords_replace(strdup(mod->first), &first_len, client->reqType, &http_req);
                if (first == NULL)
                    goto error;
                p = memchr(http_req.header, '\n', http_req.header_len);
                if (p == NULL)
                {
                    free(http_req.header);
                    http_req.header = first;
                    http_req.header_len = first_len;
                }
                else
                {
                    p++;
                    if (p - http_req.header >= first_len)
                    {
                        memmove(http_req.header + first_len, p, http_req.header_len - (p - http_req.header) + 1);
                        http_req.header_len -= (p - http_req.header) - first_len;
                    }
                    else
                    {
                        new_header = (char *)malloc(first_len + http_req.header_len - (p - http_req.header) + 1);
                        if (new_header == NULL)
                        {
                            free(first);
                            goto error;
                        }
                        memcpy(new_header + first_len, p, http_req.header_len - (p - http_req.header) + 1);
                        http_req.header_len += first_len - (p - http_req.header);
                        free(http_req.header);
                        http_req.header = new_header;
                    }
                    memcpy(http_req.header, first, first_len);
                    free(first);
                }
            break;

                default:
                    src_len = mod->src_len;
                    dest_len = mod->dest_len;
                    src = keywords_replace(strdup(mod->src), &src_len, client->reqType, &http_req);
                    dest = keywords_replace(strdup(mod->dest), &dest_len, client->reqType, &http_req);
                    if (mod->flag == STRREP)
                        http_req.header = replace(http_req.header, &http_req.header_len, src, src_len, dest, dest_len);
                    else  //正则替换
                        http_req.header = regrep(http_req.header, &http_req.header_len, src, dest, dest_len);
                    free(src);
                    free(dest);
                    if (http_req.header == NULL)
                        goto error;
                break;
        }
        mod = mod->next;
    }

    /* 连接修改后的请求头和其他数据 */
    if (client->ready_data)
    {
        p = (char *)realloc(client->ready_data, client->ready_data_len + http_req.header_len);
        if (p == NULL)
            goto error;
        client->ready_data = p;
        memcpy(p + client->ready_data_len, http_req.header, http_req.header_len);
        client->ready_data_len += http_req.header_len;
    }
    else
    {
        client->ready_data = http_req.header;
        client->ready_data_len = http_req.header_len;
        http_req.header = NULL;
    }
    if (http_req.other)
    {
        //严格模式，修改所有请求头
        if (conf.strict_modify)
        {
            int8_t type = client->reqType;
            client->reqType = request_type(http_req.other);
            if (modify_request(http_req.other, http_req.other_len, client) != 0)
            {
                http_req.other = NULL;
                goto error;
            }
            http_req.other = NULL;
            client->reqType = type;
        }
        else
        {
            p = (char *)realloc(client->ready_data, client->ready_data_len + http_req.other_len);
            if (p == NULL)
                goto error;
            client->ready_data = p;
            memcpy(p + client->ready_data_len, http_req.other, http_req.other_len);
            client->ready_data_len += http_req.other_len;
        }
    }

    //检测状态uri
    if (http_req.uri && strcmp(http_req.uri, "/cp") == 0)
    {
        rsp_stats_msg(client, http_req.host);
        free_http_request(&http_req);
        return 1;
    }
    //记录Host，之后构建CONNECT请求可能需要
    if ((client+1)->fd < 0)
    {
        client->host = http_req.host;
        http_req.host = NULL;
    }
    free_http_request(&http_req);
    return 0;

    error:
    free_http_request(&http_req);
    return -1;
}

