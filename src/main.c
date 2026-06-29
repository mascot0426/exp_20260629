/**
 * @file    main.c
 * @brief   主程序入口 - 命令行参数解析骨架
 * @author  成员B
 * @date    Day1
 *
 * 用法:
 *   实时抓包: sudo ./packet_analyzer -i eth0 -c 100
 *   带过滤:   sudo ./packet_analyzer -i eth0 -f "tcp port 80" -c 50
 *   存盘:     sudo ./packet_analyzer -i eth0 -w capture.pcap -c 100
 *   回放:     ./packet_analyzer -r capture.pcap
 *   列设备:   ./packet_analyzer -l
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* 全局运行状态(用于信号处理) */
static volatile int g_running = 1;

/* 信号处理: Ctrl+C 优雅退出 */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    printf("\n[main] 收到退出信号，正在停止...\n");
}

/* 打印用法 */
static void print_usage(const char *prog)
{
    printf("网络数据包捕获与协议解析工具 v1.0\n");
    printf("用法: %s [选项]\n\n", prog);
    printf("选项:\n");
    printf("  -i <interface>  网卡接口名 (实时抓包)\n");
    printf("  -f <filter>     BPF过滤表达式\n");
    printf("  -r <file>       从PCAP文件回放\n");
    printf("  -w <file>       保存到PCAP文件\n");
    printf("  -c <count>      抓包数量 (-1为无限, 默认10)\n");
    printf("  -l              列出可用网卡\n");
    printf("  -s              显示统计报告\n");
    printf("  -h              显示帮助\n\n");
    printf("示例:\n");
    printf("  %s -i eth0 -c 100              # 抓取100个包\n", prog);
    printf("  %s -i eth0 -f \"tcp port 80\"    # 只抓80端口TCP流量\n", prog);
    printf("  %s -r capture.pcap -s           # 回放并显示统计\n", prog);
}

/* 列出可用网卡设备 */
static void list_devices(void)
{
    /* TODO: Day2 实现capture模块后接入 */
    printf("[main] 网卡列表功能将在 Day2 capture模块完成后实现\n");
    printf("  可使用 `ip link show` 或 `ifconfig` 查看可用网卡\n");
}

int main(int argc, char **argv)
{
    char *device     = NULL;
    char *filter_str = NULL;
    char *read_file  = NULL;
    char *write_file = NULL;
    int   count      = 10;
    int   show_stats = 0;
    int   opt;

    /* 命令行参数解析 */
    while ((opt = getopt(argc, argv, "i:f:r:w:c:lsh")) != -1) {
        switch (opt) {
            case 'i': device     = optarg;       break;
            case 'f': filter_str = optarg;       break;
            case 'r': read_file  = optarg;       break;
            case 'w': write_file = optarg;       break;
            case 'c': count      = atoi(optarg); break;
            case 'l': list_devices();            return 0;
            case 's': show_stats = 1;            break;
            case 'h': print_usage(argv[0]);      return 0;
            default:  print_usage(argv[0]);      return 1;
        }
    }

    /* 无参数则显示帮助 */
    if (device == NULL && read_file == NULL) {
        print_usage(argv[0]);
        return 0;
    }

    /* 注册信号处理 */
    signal(SIGINT, signal_handler);

    /* 打印解析结果(骨架阶段验证参数解析是否正常) */
    printf("[main] 参数解析结果:\n");
    if (device)     printf("  网卡接口  : %s\n", device);
    if (filter_str) printf("  过滤表达式: %s\n", filter_str);
    if (read_file)  printf("  读取文件  : %s\n", read_file);
    if (write_file) printf("  保存文件  : %s\n", write_file);
    printf("  抓包数量  : %d\n", count);
    printf("  显示统计  : %s\n", show_stats ? "是" : "否");

    /* TODO: Day2 起逐步接入以下模块 */
    /*   - capture: 抓包引擎      (Day2, 成员A) */
    /*   - parser:  协议解析      (Day3, 成员A) */
    /*   - filter:  BPF过滤       (Day5, 成员A) */
    /*   - stats:   流量统计      (Day2, 成员B) */
    /*   - pcap_io: PCAP读写      (Day6, 成员B) */

    if (read_file != NULL) {
        /* TODO: Day6 实现PCAP离线回放 */
        printf("[main] 离线回放模式: 模块待接入(Day6)\n");
    } else {
        /* TODO: Day2 实现实时抓包 */
        printf("[main] 实时抓包模式: 模块待接入(Day2)\n");
    }

    printf("[main] 骨架阶段完成，参数解析正常\n");

    return 0;
}
