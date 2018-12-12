#include <dirent.h>
#include "main.h"

#define SERVICE_TYPE_STOP 1
#define SERVICE_TYPE_STATUS 2
#define SERVICE_TYPE_STATUS_NOT_PRINT 3

char *get_proc_name(char *path)
{
    char proc_name[257];
    FILE *fp;
    int readsize;
    
    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;
    readsize = fread(proc_name, 1, 256, fp);
    fclose (fp);
    return strndup(proc_name, readsize - 1);
}

int8_t additional_service(char *self_name, uint8_t service_type)
{
    char commpath[270];
    DIR *DP;
    struct dirent *dp;
    char *proc_name;
    pid_t self_pid;

    DP = opendir("/proc");
    if (DP == NULL)
        return 1;
    proc_name = strrchr(self_name, '/');
    if (proc_name)
        self_name = proc_name + 1;
    self_pid = getpid();
    while ((dp = readdir(DP)) != NULL)
    {
        if (dp->d_type != DT_DIR)
            continue;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0 || atoi(dp->d_name) == self_pid)
            continue;
        sprintf(commpath, "/proc/%s/comm", dp->d_name);
        proc_name = get_proc_name(commpath);
        if (proc_name == NULL)
            continue;
        if (strcmp(proc_name, self_name) == 0)
        {
            if (service_type == SERVICE_TYPE_STOP)
                kill(atoi(dp->d_name), SIGTERM);
            else
            {
                free(proc_name);
                closedir(DP);
                if (service_type != SERVICE_TYPE_STATUS_NOT_PRINT)
                    printf("✔  %s(" VERSION ") 正在运行\n", self_name);
                return 0;
            }
        }
        free(proc_name);
    }
    closedir(DP);

    if (service_type == SERVICE_TYPE_STATUS)
        printf("✘  %s(" VERSION ") 没有运行\n", self_name);
    else if (service_type == SERVICE_TYPE_STATUS_NOT_PRINT)
        return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    pthread_t thread_id;

    /* 命令行选项 */
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        puts("ChameleonProxy(" VERSION ")\n"
        "启动命令:\n    CProxy CProxy.conf\n"
        "结束命令:\n    CProxy stop\n"
        "检测命令:\n    CProxy status\n");
        return argc < 2 ? 1 : 0;
    }
    if (strcasecmp(argv[1], "stop") == 0)
        return additional_service(argv[0], SERVICE_TYPE_STOP);
    else if (strcasecmp(argv[1], "status") == 0)
        return additional_service(argv[0], SERVICE_TYPE_STATUS);
    else if (strcasecmp(argv[1], "restart") == 0)
    {
        additional_service(argv[0], SERVICE_TYPE_STOP);
        while (additional_service(argv[0], SERVICE_TYPE_STATUS_NOT_PRINT) == 0);
        argv++;
    }

    /* 初始化 */
    read_conf(argv[1]);
    signal(SIGPIPE, SIG_IGN);
    //不能用setgid和setuid，这两个函数不能切换回root，可能导致HTTPUDP代理失败
    if (conf.uid > -1 && (setegid(conf.uid) == -1 || seteuid(conf.uid) == -1))
    {
        perror("setegid(or seteuid)");
        return 1;
    }
    #ifdef DEBUG
    if (daemon(1, 1) == -1)
    #else
    if (daemon(1, 0) == -1)
    #endif
    {
        perror("daemon()");
        return 1;
    }
    /*
    一个进程只开一个子进程，
    程序结束时子进程先写入dns缓存，
    之后主进程再写入，
    否则可能导致缓存文件格式错误
    */
    while (conf.procs-- > 1 && (child_pid = fork()) == 0);
    /* 服务开始 */
    if (conf.tcp_listen_fd >= 0)
    {
        tcp_init();  //必须在此处先初始化   否则可能dns或者UDP初始化生成不了CONNECT请求
        if (conf.dns_listen_fd >= 0)
        {
            pthread_create(&thread_id, NULL, &dns_loop, NULL);
        }
        if (conf.udp_listen_fd >= 0)
        {
            pthread_create(&thread_id, NULL, &udp_loop, NULL);
        }
        tcp_loop();
    }
    if (conf.dns_listen_fd >= 0)
    {
        if (conf.udp_listen_fd >= 0)
        {
            pthread_create(&thread_id, NULL, &udp_loop, NULL);
        }
        dns_loop(NULL);
    }
    udp_loop(NULL);

    return 0;
}



