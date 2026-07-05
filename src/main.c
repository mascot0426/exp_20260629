/**
 * @file    main.c
 * @brief   主程序入口 - 命令行参数解析 + 模块调度
 *          增强版：支持静默模式(性能测试) + HTTP请求响应配对报告
 *
 * 用法:
 *   实时抓包: sudo ./packet_analyzer -i eth0 -c 100
 *   带过滤:   sudo ./packet_analyzer -i eth0 -f "tcp port 80" -c 50
 *   存盘:     sudo ./packet_analyzer -i eth0 -w capture.pcap -c 100
 *   回放:     ./packet_analyzer -r capture.pcap
 *   列设备:   ./packet_analyzer -l
 *   静默模式: sudo ./packet_analyzer -i eth0 -q -c 10000  (性能测试)
 */

#include "packet.h"
#include "capture.h"
#include "parser.h"
#include "filter.h"
#include "stats.h"
#include "pcap_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* 应用上下文: 同时传递统计和存盘句柄给回调 */
typedef struct {
    stats_ctx_t   *stats;
    pcap_dumper_t *dumper;   /* NULL表示不存盘 */
    int            quiet;      /* 静默模式(不打印每个包) */
} app_ctx_t;

/* 全局状态(用于信号处理) */
static capture_ctx_t  g_capture_ctx;
static stats_ctx_t    g_stats_ctx;
static pcap_save_ctx_t *g_save_ctx = NULL;
static volatile int   g_running = 1;

/* 信号处理: Ctrl+C 优雅退出 */
static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    capture_stop(&g_capture_ctx);
}

/* 每秒统计刷新回调 */
static void on_stats_refresh(void *user_data)
{
    stats_ctx_t *stats = (stats_ctx_t *)user_data;
    stats_print_brief(stats);
}

/* 数据包回调: 解析后打印(可选) + 更新统计 + 存盘 */
static void on_packet(const packet_info_t *pkt, void *user_data)
{
    app_ctx_t *app = (app_ctx_t *)user_data;

    /* 打印数据包信息(仅在非静默模式) */
    if (!app->quiet) {
        packet_print(pkt);
    }

    /* 更新统计 */
    stats_update(app->stats, pkt);

    /* 存盘(如果开启) */
    if (app->dumper) {
        struct pcap_pkthdr hdr;
        hdr.ts     = pkt->ts;
        hdr.caplen = pkt->cap_len;
        hdr.len    = pkt->orig_len;
        pcap_dump((u_char *)app->dumper, &hdr, pkt->raw_data);
    }
}

/* 回放模式的pcap回调(直接使用libpcap原始回调) */
static void replay_callback(u_char *user, const struct pcap_pkthdr *header,
                            const u_char *packet)
{
    app_ctx_t *app = (app_ctx_t *)user;
    packet_info_t pkt;
    parse_packet(packet, header->caplen, header->len, header->ts, &pkt);

    if (!app->quiet) {
        packet_print(&pkt);
    }
    stats_update(app->stats, &pkt);

    /* 回放时也可存盘 */
    if (app->dumper) {
        pcap_dump((u_char *)app->dumper, header, packet);
    }
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
    printf("  -q              静默模式(不打印每个包,用于性能测试)\n");
    printf("  -h              显示帮助\n\n");
    filter_print_examples();
}

int main(int argc, char **argv)
{
    char *device     = NULL;
    char *filter_str = NULL;
    char *read_file  = NULL;
    char *write_file = NULL;
    int   count      = 10;
    int   show_stats = 0;
    int   quiet      = 0;  /* 静默模式 */
    int   opt;

    /* 命令行参数解析 */
    while ((opt = getopt(argc, argv, "i:f:r:w:c:lsqh")) != -1) {
        switch (opt) {
            case 'i': device     = optarg;     break;
            case 'f': filter_str = optarg;     break;
            case 'r': read_file  = optarg;     break;
            case 'w': write_file = optarg;     break;
            case 'c': count      = atoi(optarg); break;
            case 'l': capture_list_devices(); return 0;
            case 's': show_stats = 1;          break;
            case 'q': quiet      = 1;          break;
            case 'h': print_usage(argv[0]);    return 0;
            default:  print_usage(argv[0]);    return 1;
        }
    }

    /* 无参数则显示帮助 */
    if (device == NULL && read_file == NULL) {
        print_usage(argv[0]);
        return 0;
    }

    /* 注册信号处理 */
    signal(SIGINT, signal_handler);

    /* 初始化统计模块 */
    stats_init(&g_stats_ctx);

    /* 初始化HTTP流跟踪 */
    http_flow_init();

    /* 应用上下文(统计 + 存盘 + 静默模式) */
    app_ctx_t app_ctx;
    app_ctx.stats  = &g_stats_ctx;
    app_ctx.dumper = NULL;
    app_ctx.quiet  = quiet;

    if (read_file != NULL) {
        /* ===== 离线回放模式 ===== */

        /* 如果指定了存盘, 用读文件打开dumper(dumper独立于handle, 可安全关闭) */
        if (write_file != NULL) {
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *tmp = pcap_open_offline(read_file, errbuf);
            if (tmp == NULL) {
                fprintf(stderr, "[main] 无法打开离线文件: %s\n", errbuf);
                return 1;
            }
            g_save_ctx = pcap_save_open(tmp, write_file);
            pcap_close(tmp); /* dumper独立, 关闭tmp安全 */
            if (g_save_ctx) {
                app_ctx.dumper = g_save_ctx->dumper;
            }
        }

        if (pcap_replay_loop(read_file, filter_str, replay_callback,
                             (u_char *)&app_ctx) != 0) {
            if (g_save_ctx) pcap_save_close(g_save_ctx);
            stats_destroy(&g_stats_ctx);
            http_flow_destroy();
            return 1;
        }

    } else {
        /* ===== 实时抓包模式 ===== */

        /* Step 1: 初始化 + 打开设备 */
        capture_init(&g_capture_ctx, device, 1); /* 混杂模式 */
        if (capture_open(&g_capture_ctx) != 0) {
            stats_destroy(&g_stats_ctx);
            http_flow_destroy();
            return 1;
        }

        /* Step 2: 设置BPF过滤器(在loop之前! 否则不生效) */
        if (filter_str != NULL) {
            pcap_t *handle = capture_get_handle(&g_capture_ctx);
            struct bpf_program fp;
            bpf_u_int32 net, mask;
            pcap_lookupnet(g_capture_ctx.device, &net, &mask, g_capture_ctx.errbuf);
            if (filter_compile(handle, &fp, filter_str, mask) == 0) {
                filter_apply(handle, &fp);
                filter_free(&fp);
            } else {
                fprintf(stderr, "[main] 过滤器设置失败, 将抓取所有包\n");
            }
        }

        /* Step 3: 打开存盘文件(在loop之前! 否则前面的包不会保存) */
        if (write_file != NULL) {
            pcap_t *handle = capture_get_handle(&g_capture_ctx);
            g_save_ctx = pcap_save_open(handle, write_file);
            if (g_save_ctx) {
                app_ctx.dumper = g_save_ctx->dumper;
            } else {
                fprintf(stderr, "[main] 存盘文件打开失败, 将不保存\n");
            }
        }

        /* Step 4: 设置数据包回调 */
        capture_set_callback(&g_capture_ctx, on_packet, &app_ctx);

        /* Step 5: 设置每秒统计回调 */
        capture_set_stats_callback(&g_capture_ctx, on_stats_refresh, &g_stats_ctx);

        /* Step 5.5: 静默模式启用快速模式(跳过完整解析,提升性能) */
        if (quiet) {
            capture_set_fast_mode(&g_capture_ctx, 1);
        }

        /* Step 6: 启动抓包循环(阻塞, 每秒刷新统计) */
        capture_loop(&g_capture_ctx, count);

        /* Step 7: 清理 */
        capture_destroy(&g_capture_ctx);
    }

    /* 换行, 避免与实时统计行重叠 */
    printf("\n");

    /* 显示完整统计报告 */
    if (show_stats || g_stats_ctx.proto_stats.total_packets > 0) {
        stats_print(&g_stats_ctx);
    }

    /* 打印HTTP请求/响应配对结果 */
    http_flow_print_pairs();

    /* 清理存盘 */
    if (g_save_ctx) {
        pcap_save_close(g_save_ctx);
    }
    stats_destroy(&g_stats_ctx);
    http_flow_destroy();

    return 0;
}
