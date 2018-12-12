#include "common.h"

struct sockaddr_in addr;
socklen_t addr_len = sizeof(addr);

void error(const char *error_info)
{
    fprintf(stderr, "%s\n\n", error_info);
    exit(1);
}

/* 字符串替换，replace_memory为可以用free释放的指针 */
char *replace(char *replace_memory, int *replace_memory_len, const char *src, const int src_len, const char *dest, const int dest_len)
{
    if (!replace_memory || !src || !dest)
        return replace_memory;

    char *p;
    int diff;

    if (src_len == dest_len)
    {
        for (p = memmem(replace_memory, *replace_memory_len, src, src_len); p; p = memmem(p, *replace_memory_len - (p - replace_memory), src, src_len))
        {
            memcpy(p, dest, dest_len);
            p += dest_len;
        }
    }
    else if (src_len < dest_len)
    {
        int before_len;
        char *before_end, *new_replace_memory;

        diff = dest_len - src_len;
        for (p = memmem(replace_memory, *replace_memory_len, src, src_len); p; p = memmem(p, *replace_memory_len - (p - replace_memory), src, src_len))
        {
            *replace_memory_len += diff;
            before_len = p - replace_memory;
            new_replace_memory = (char *)realloc(replace_memory, *replace_memory_len + 1);
            if (new_replace_memory == NULL)
            {
                free(replace_memory);
                return NULL;
            }
            replace_memory = new_replace_memory;
            before_end = replace_memory + before_len;
            p = before_end + dest_len;
            memmove(p, p - diff, *replace_memory_len - (p - replace_memory));
            memcpy(before_end, dest, dest_len);
        }
    }
    else if (src_len > dest_len)
    {
        diff = src_len - dest_len;
        for (p = memmem(replace_memory, *replace_memory_len, src, src_len); p; p = memmem(p, *replace_memory_len - (p - replace_memory), src, src_len))
        {
            *replace_memory_len -= diff;
            memcpy(p, dest, dest_len);
            p += dest_len;
            memmove(p, p + diff, *replace_memory_len - (p - replace_memory));
        }
    }

    replace_memory[*replace_memory_len] = '\0';
    return replace_memory;
}

/* 对数据进行编码 */
void dataEncode(char *data, int data_len, int8_t code)
{
    while (data_len-- > 0)
        data[data_len] ^= code;
}

/* 监听一个UDP接口 */
int udp_listen(char *ip, int port)
{
    int fd, opt = 1;

    if ((fd=socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("udp socket()");
        exit(1);
    }
    setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt));
    setsockopt(fd, SOL_IP, IP_RECVORIGDSTADDR, &opt, sizeof(opt));
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = inet_addr(ip);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("udp bind()");
        exit(1);
    }

    return fd;
}
