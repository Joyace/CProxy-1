#include <dirent.h>
#include <sys/wait.h>
#include "main.h"

#define SERVICE_TYPE_STOP 1
#define SERVICE_TYPE_STATUS 2

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

    chdir("/proc");
    DP = opendir(".");
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
        sprintf(commpath, "%s/comm", dp->d_name);
        proc_name = get_proc_name(commpath);
        if (proc_name == NULL)
            continue;
        if (strcmp(proc_name, self_name) == 0)
        {
            if (service_type == SERVICE_TYPE_STOP)
                kill(atoi(dp->d_name), SIGTERM);
            else
            {
                printf("✔  %s(" VERSION ") 正在运行\n", self_name);
                free(proc_name);
                closedir(DP);
                return 0;
            }
        }
        free(proc_name);
    }
    closedir(DP);

    if (service_type == SERVICE_TYPE_STATUS)
        printf("✘  %s(" VERSION ") 没有运行\n", self_name);
    return 0;
}

int main(int argc, char *argv[])
{
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
    /* 关闭文件描述符，0, 1, 2除外 */
    int fd;
    for (fd = 3; fd < 1024; fd++)
        close(fd);
    /* 初始化 */
    read_conf(argv[1]);
    signal(SIGPIPE, SIG_IGN);
    if (conf.uid > -1 && (setgid(conf.uid) == -1 || setuid(conf.uid) == -1))
    {
        perror("setuid");
        return 1;
    }
    if (daemon(1, 1) == -1)
    {
        perror("daemon");
        return 1;
    }
    /* 关闭0, 1, 2文件描述符 */
    #ifndef DEBUG
    for (fd = 0; fd < 3; fd++)
        close(fd);
    #endif
    /*
    一个进程只开一个子进程，
    程序结束时子进程先写入dns缓存，
    之后主进程再写入，
    否则可能导致缓存文件格式错误
    */
    while (conf.procs-- > 1 && (child_pid = fork()) == 0);
    /* 服务开始 */
    if (conf.dns_listen_fd > 0)
    {
        dns_init();
        if (conf.tcp_listen_fd > 0)
        {
            pthread_t thread_id;
            pthread_create(&thread_id, NULL, dns_loop, NULL);
        }
        else
            dns_loop();
    }
    if (conf.tcp_listen_fd > 0)
    {
        tcp_init();
        tcp_loop();
    }

    return 0;
}



