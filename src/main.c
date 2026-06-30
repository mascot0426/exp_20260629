/**
 * @file    main.c
 * @brief   主程序入口 - 命令行参数解析 + 调用抓包与统计模块
 *
 * Day2 更新: 接入 capture 抓包引擎 + stats 统计模块
 *   - 实时抓包: 注册回调，抓包过程中更新统计
 *   - 抓包结束后打印统计报告
 *
 * 用法:
 *   实时抓包: sudo ./packet_analyzer -i eth0 -c 100
 *   列设备:   ./packet_analyzer -l
 *
 * TODO (后续天数):
 *   - Day5: 集成 BPF 过滤器 (-f 参数)
 *   - Day6: 集成 PCAP 存盘/回放 (-w / -r 参数)
 *   - Day7: 每秒统计刷新
 *   - Day8: 完整版整合所有模块
 */

#include "packet.h"
#include "capture.h"
#include "stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* 全局状态 (用于信号处理) */
static capture_ctx_t  g_capture_ctx;
static stats_ctx_t    g_stats_ctx;
static volatile int   g_running = 1;

/* 信号处理: Ctrl+C 优雅退出 */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    capture_stop(&g_capture_ctx);
}

/* 数据包回调: 抓到包后更新统计 */
static void on_packet(const packet_info_t *pkt, void *user_data)
{
    stats_ctx_t *stats = (stats_ctx_t *)user_data;

    /* 打印数据包基本信息 (Day2 简版，parser 未接入) */
    printf("[packet] len=%u cap=%u\n",
           pkt->orig_len, pkt->cap_len);

    /* 更新统计 */
    stats_update(stats, pkt);
}

/* 打印用法 */
static void print_usage(const char *prog)
{
    printf("网络数据包捕获与协议解析工具 v1.0\n");
    printf("用法: %s [选项]\n\n", prog);
    printf("选项:\n");
    printf("  -i <interface>  网卡接口名 (实时抓包)\n");
    printf("  -f <filter>     BPF过滤表达式 (Day5 实现)\n");
    printf("  -r <file>       从PCAP文件回放 (Day6 实现)\n");
    printf("  -w <file>       保存到PCAP文件 (Day6 实现)\n");
    printf("  -c <count>      抓包数量 (-1为无限, 默认10)\n");
    printf("  -l              列出可用网卡\n");
    printf("  -s              显示统计报告\n");
    printf("  -h              显示帮助\n\n");
    printf("示例:\n");
    printf("  %s -i eth0 -c 100              # 抓取100个包\n", prog);
    printf("  %s -l                           # 列出可用网卡\n", prog);
}

int main(int argc, char **argv)
{
    char *device     = NULL;
    char *filter_str = NULL;  /* Day5 实现 */
    char *read_file  = NULL;  /* Day6 实现 */
    char *write_file = NULL;  /* Day6 实现 */
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
            case 'l': capture_list_devices();    return 0;
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

    /* Day2: 仅支持实时抓包模式，离线回放 Day6 实现 */
    if (read_file != NULL) {
        printf("[main] 离线回放模式将在 Day6 实现\n");
        return 0;
    }

    /* Day2: 过滤器/存盘尚未实现 */
    if (filter_str != NULL) {
        printf("[main] 注意: BPF过滤器将在 Day5 实现，当前抓取所有包\n");
    }
    if (write_file != NULL) {
        printf("[main] 注意: PCAP存盘将在 Day6 实现\n");
    }

    /* 注册信号处理 */
    signal(SIGINT, signal_handler);

    /* 初始化统计模块 */
    stats_init(&g_stats_ctx);

    /* ===== 实时抓包模式 ===== */

    /* Step 1: 初始化 + 打开设备 */
    capture_init(&g_capture_ctx, device, 1);  /* 混杂模式 */
    if (capture_open(&g_capture_ctx) != 0) {
        fprintf(stderr, "[main] 打开网卡设备失败\n");
        stats_destroy(&g_stats_ctx);
        return 1;
    }

    /* Step 2: 设置数据包回调 (回调中更新统计) */
    capture_set_callback(&g_capture_ctx, on_packet, &g_stats_ctx);

    /* Step 3: 启动抓包循环 (阻塞) */
    printf("[main] 开始抓包 (设备: %s, 数量: %d)\n", device, count);
    capture_loop(&g_capture_ctx, count);

    /* Step 4: 清理抓包资源 */
    capture_destroy(&g_capture_ctx);

    /* 显示统计报告 */
    printf("\n");
    if (show_stats || g_stats_ctx.proto_stats.total_packets > 0) {
        stats_print(&g_stats_ctx);
    }

    /* 清理统计资源 */
    stats_destroy(&g_stats_ctx);

    return 0;
}
