#include "conf.h"

struct config conf;

/* HTTPS模式的字符串提前修改 */
char *ssl_req_replace(char *str)
{
    int len = strlen(str);
    str = replace(str, &len, "[M]", 3, "CONNECT", 7);
    str = replace(str, &len, "[V]", 3, "HTTP/1.1", 8);
    str = replace(str, &len, "[U]", 3, "/", 1);
    return replace(str, &len, "[url]", 5, "[H]", 3);
}

/* 字符串预处理 */
void string_pretreatment(char *str)
{
    int len;
    
    //删除换行和缩进
    char *lf, *p;
    while ((lf = strchr(str, '\n')) != NULL)
    {
        for (p = lf + 1; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++);
        strcpy(lf, p);
    }
    len = strlen(str);
    replace(str, &len, "\r", 1, "", 0);  //Windows换行是\r\n

    //替换转义字符
    replace(str, &len, "\\b", 2, "\b", 1);
    replace(str, &len, "\\v", 2, "\v", 1);
    replace(str, &len, "\\f", 2, "\f", 1);
    replace(str, &len, "\\a", 2, "\a", 1);
    replace(str, &len, "\\t", 2, "\t", 1);
    replace(str, &len, "\\r", 2, "\r", 1);
    replace(str, &len, "\\n", 2, "\n", 1);
}

/* 在content中，设置变量(var)的首地址，值(val)的位置首地址和末地址 */
int8_t set_var_val(char *content, char **var, char **val_begin, char **val_end)
{
    char *p, *pn;

    while (1)
    {
        if (content == NULL)
            return 1;

        for (;*content == ' ' || *content == '\t' || *content == '\r' || *content == '\n'; content++);
        if (*content == '\0')
            return 1;
        *var = content;
        pn = strchr(content, '\n');
        p = strchr(content, '=');
        if (p == NULL)
        {
            if (pn)
            {
                content = pn + 1;
                continue;
            }
            else
                return 1;
        }
        content = p;
        //将变量以\0结束
        for (p--; *p == ' ' || *p == '\t'; p--);
        *(p+1) = '\0';
        //值的首地址
        for (content++; *content == ' ' || *content == '\t'; content++);
        if (*content == '\0')
            return 1;
        //双引号引起来的值支持换行
        if (*content == '"')
        {
            *val_begin = content + 1;
            *val_end = strstr(*val_begin, "\";");
            if (*val_end != NULL)
                break;
        }
        else
            *val_begin = content;
        *val_end = strchr(content, ';');
        if (*val_end == NULL)
            return 1;
        if (pn && *val_end > pn)
        {
            content = pn + 1;
            continue;
        }
        break;
    }

    *(*val_end)++ = '\0';
    string_pretreatment(*val_begin);
    //printf("var[%s]\nbegin[%s]\n\n", *var, *val_begin);
    return 0;
}

/* 在buff中读取模块(global http https httpdns)内容 */
char *read_module(char *buff, const char *module_name)
{
    int len;
    char *p, *p0;

    len = strlen(module_name);
    p = buff;
    while (1)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (strncasecmp(p, module_name, len) == 0)
        {
            p += len;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
                p++;
            if (*p == '{')
                break;
        }
        if ((p = strchr(p, '\n')) == NULL)
            return NULL;
    }
    if ((p0 = strchr(++p, '}')) == NULL)
        return NULL;

    //printf("%s\n%s", module_name, content);
    return strndup(p, p0 - p);
}

void parse_global_module(char *content)
{
    char *var, *val_begin, *val_end, *p;

    while (set_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "mode") == 0)
        {
            if (strcasecmp(val_begin, "wap_connect") == 0)
                conf.mode = WAP_CONNECT;
           else  if (strcasecmp(val_begin, "wap") == 0)
                conf.mode = WAP;
           else  if (strcasecmp(val_begin, "net_connect") == 0)
                conf.mode = NET_CONNECT;
           else  if (strcasecmp(val_begin, "net_proxy") == 0)
                conf.mode = NET_PROXY;
        }
        else if (strcasecmp(var, "uid") == 0)
        {
            conf.uid = atoi(val_begin);
        }
        else if (strcasecmp(var, "procs") == 0)
        {
            conf.procs = atol(val_begin);
        }
        else if (strcasecmp(var, "tcp_listen") == 0l)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                conf.tcp_listen_fd = tcp_listen(val_begin, atoi(p + 1));
            }
            else
                conf.tcp_listen_fd = tcp_listen((char *)"0.0.0.0", atoi(val_begin));
        }
        else if (strcasecmp(var, "dns_listen") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                conf.dns_listen_fd = udp_listen(val_begin, atoi(p+1));
            }
            else
                conf.dns_listen_fd = udp_listen((char *)"127.0.0.1", atoi(val_begin));
        }
        else if (strcasecmp(var, "strict") == 0 && strcasecmp(val_begin, "on") == 0)
        {
            conf.strict_modify = 1;
        }

        content = strchr(val_end, '\n');
    }
}

/* 读取TCP模块 */
int8_t parse_tcp_module(char *content, struct tcp_conf *tcp,int8_t https)
{
    struct modify *m, *m_save;
    struct ssl_string *s;
    char *var, *val_begin, *val_end, *p, *src_end, *dest_begin;

    m = NULL;
    s = ssl_str;
    while(set_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(atoi(p + 1));
            }
            else
            {
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(80);
            }
            goto next_line;
        }

        /* 以下判断为链表操作 */
        m_save = m; //保存前一个结构体指针
        if (m)
            m = m->next = (struct modify *)malloc(sizeof(*m));
        else
           tcp->m = m = (struct modify *)malloc(sizeof(*m));
        if (m == NULL)
            return 1;
        memset((struct modify *)m, 0, sizeof(*m));
        if (strcasecmp(var, "del_hdr") == 0)
        {
            m->flag = DEL_HDR;
            m->del_hdr = strdup(val_begin);
            if (m->del_hdr == NULL)
                return 1;
        }
        else if (strcasecmp(var, "set_first") == 0)
        {
            m->first = strdup(val_begin);
            //https模块首先替换部分字符串
            if (https)
                m->first = ssl_req_replace(m->first);
            if (m->first == NULL)
                return 1;
            m->first_len = strlen(m->first);
            m->flag = SET_FIRST;
        }
        else if (strcasecmp(var, "strrep") == 0 || strcasecmp(var, "regrep") == 0)
        {
            //定位 [源字符串结束地址] 和 [目标字符串首地址]
            p = strstr(val_begin, "->");
            if (p == NULL)
                return 1;
            for (src_end = p - 1; *src_end == ' '; src_end--)
            {
                if (src_end == val_begin)
                    return 1;
            }
            if (*src_end == '"')
                src_end--;
            for (dest_begin = p + 2; *dest_begin == ' '; dest_begin++)
            {
                if (dest_begin == val_end)
                    return 1;
            }
            if (*dest_begin == '"')
                dest_begin++;
            //复制原字符串
            m->src = strndup(val_begin, src_end - val_begin + 1);
            //复制目标字符串
            if (val_end - dest_begin - 1 <= 0) //如果目标字符串为空
                m->dest = (char *)calloc(1, 1);
            else
                m->dest = strdup(dest_begin);
            if (https)
            {
                m->src = ssl_req_replace(m->src);
                m->dest = ssl_req_replace(m->dest);
            }
            if (m->src == NULL || m->dest == NULL)
                return 1;
            m->src_len = strlen(m->src);
            m->dest_len = strlen(m->dest);
            if (*var == 's')  //如果是普通字符串替换
                m->flag = STRREP;
            else  //正则表达式字符串替换
                m->flag = REGREP;
        }
        else if (https == 0)
        {
            if (strcasecmp(var, "only_get_post") == 0 && strcasecmp(val_begin, "on") == 0)
            {
                conf.http_only_get_post = 1;
            }
            else if (strcasecmp(var, "proxy_https_string") == 0)
            {
                s = (struct ssl_string *)malloc(sizeof(*s));
                if (s == NULL)
                    return 1;
                s->str = strdup(val_begin);
                if (s->str == NULL)
                    return 1;
                s->next = ssl_str;
                ssl_str = s;
            }
        }
        if (m->flag == 0)
        {
            free(m);
            if (m_save)
            {
                m = m_save;
                m->next = NULL;
            }
            else
                tcp->m = m = NULL;
        }

        next_line:
        content = strchr(val_end, '\n');
    }

    return 0;
}

/* 读取HTTPDNS模块 */
int8_t parse_httpdns_module(char *content)
{
    char *var, *val_begin, *val_end, *p;

    while (set_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ( (p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                conf.dns.dst.sin_port = htons(atoi(p+1));
            }
            else
            {
                conf.dns.dst.sin_port = htons(80);
            }
            conf.dns.dst.sin_addr.s_addr = inet_addr(val_begin);
        }
        else if(strcasecmp(var, "http_req") == 0)
        {
            conf.dns.http_req = strdup(val_begin);
            if (conf.dns.http_req == NULL)
                return 1;
        }
        else if (strcasecmp(var, "cachePath") == 0)
        {
            conf.dns.cachePath = strdup(val_begin);
            if (conf.dns.cachePath == NULL || read_cache_file() != 0)
                return 1;
        }
        else if (strcasecmp(var, "cacheLimit") == 0)
        {
            conf.dns.cacheLimit = atoi(val_begin);
        }

        content = strchr(val_end, '\n');
    }

    return 0;
}

void read_conf(char *path)
{
    char *buff, *global, *http, *https, *httpdns;
    FILE *file;
    long file_size;

    /* 读取配置文件到缓冲区 */
    file = fopen(path, "r");
    if (file == NULL)
        error("cannot open config file.");
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    buff = (char *)alloca(file_size + 1);
    if (buff == NULL)
        error("out of memory.");
    rewind(file);
    fread(buff, file_size, 1, file);
    fclose(file);
    buff[file_size] = '\0';

    memset((struct config *)&conf, 0, sizeof(conf));
    conf.http.dst.sin_family = conf.https.dst.sin_family = conf.dns.dst.sin_family = AF_INET;
    conf.uid = -1;
    /* 读取global模块内容 */
    if ((global = read_module(buff, "global")) == NULL)
        error("wrong config file or out of memory.");
    parse_global_module(global);
    free(global);

    if (conf.tcp_listen_fd)
    {
        /* 读取http模块内容 */
        if (((http = read_module(buff, "http")) == NULL) || parse_tcp_module(http, &conf.http, 0) != 0)
            error("wrong config file or out of memory.");
        free(http);
    
        /* 读取https模块 */
        if (((https = read_module(buff, "https")) == NULL) || parse_tcp_module(https, &conf.https, 1) != 0)
            error("wrong config file or out of memory.");
        free(https);
    }

    /* 读取httpdns模块 */
    if (conf.dns_listen_fd)
    {
        if ((httpdns = read_module(buff, "httpdns")) == NULL || parse_httpdns_module(httpdns) != 0)
            error("wrong config file or out of memory.");
        free(httpdns);
    }
}
