/**
 * @file    capture.c
 * @brief   libpcap抓包引擎实现
 *
 * 核心流程: pcap_findalldevs -> pcap_open_live -> pcap_dispatch(循环) -> 回调
 * 参考代码: sniffex.c + 腾讯云开发者文章
 *
 * 架构改进(修复过滤器/存盘时序bug):
 *   旧版 capture_start 将 open+loop 混在一起，导致过滤器在 loop 之后才设置。
 *   新版拆分为 capture_open(打开设备) + capture_loop(dispatch循环)，
 *   使 main.c 能在 open 之后、loop 之前正确设置过滤器和存盘。
 *   同时用 pcap_dispatch 替代 pcap_loop，实现每秒统计刷新。
 */

#include "capture.h"
#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* 全局上下文指针(用于信号处理中中断抓包) */
static capture_ctx_t *g_ctx = NULL;

/* 内部回调: 包装parse_packet + 用户回调 */
static void internal_callback(u_char *user, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
    capture_ctx_t *ctx = (capture_ctx_t *)user;
    packet_info_t pkt;

    if (ctx->fast_mode) {
        /* 快速模式: 仅提取最小信息,跳过完整协议解析和HTTP配对 */
        memset(&pkt, 0, sizeof(pkt));
        pkt.raw_data = packet;
        pkt.cap_len  = header->caplen;
        pkt.orig_len = header->len;
        pkt.ts       = header->ts;
        pkt.parsed_ok = 1;

        /* 仅解析以太网头+IP头(14+20=34字节),不做传输层和应用层解析 */
        if (header->caplen >= 34) {
            const sniff_ethernet_t *eth = (const sniff_ethernet_t *)packet;
            pkt.eth_type = ntohs(eth->ether_type);
            if (pkt.eth_type == ETHERTYPE_IPV4) {
                const sniff_ip_t *ip = (const sniff_ip_t *)(packet + SIZE_ETHERNET);
                pkt.ip_proto = ip->ip_p;
                /* IP地址转字符串(轻量) */
                struct in_addr a;
                a.s_addr = ip->ip_src;
                inet_ntop(AF_INET, &a, pkt.src_ip, IP_STR_LEN);
                a.s_addr = ip->ip_dst;
                inet_ntop(AF_INET, &a, pkt.dst_ip, IP_STR_LEN);
            }
        }
    } else {
        /* 正常模式: 完整解析 */
        parse_packet(packet, header->caplen, header->len, header->ts, &pkt);
    }

    /* 调用用户注册的回调(统计/保存等) */
    if (ctx->callback) {
        ctx->callback(&pkt, ctx->user_data);
    }
}

void capture_init(capture_ctx_t *ctx, const char *device, int promisc)
{
    if (ctx == NULL) return;

    memset(ctx, 0, sizeof(*ctx));
    ctx->promisc  = promisc;
    ctx->snaplen  = SNAP_LEN;
    ctx->timeout  = 1000;

    if (device) {
        strncpy(ctx->device, device, sizeof(ctx->device) - 1);
    } else {
        /* 自动查找默认设备 (pcap_lookupdev已弃用，改用pcap_findalldevs) */
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, ctx->errbuf) == -1) {
            fprintf(stderr, "[capture] 查找设备失败: %s\n", ctx->errbuf);
            return;
        }
        if (alldevs != NULL) {
            strncpy(ctx->device, alldevs->name, sizeof(ctx->device) - 1);
        }
        pcap_freealldevs(alldevs);
    }

    g_ctx = ctx;
}

int capture_open(capture_ctx_t *ctx)
{
    if (ctx == NULL || ctx->device[0] == '\0') {
        fprintf(stderr, "[capture] 上下文未初始化\n");
        return -1;
    }

    /* 获取设备网络信息(用于BPF过滤) */
    bpf_u_int32 net, mask;
    if (pcap_lookupnet(ctx->device, &net, &mask, ctx->errbuf) == -1) {
        net  = 0;
        mask = 0;
        fprintf(stderr, "[capture] 警告: 无法获取网络掩码: %s\n", ctx->errbuf);
    }

    /* 使用 pcap_create + pcap_activate 流程，以便在激活前设置缓冲区大小 */
    ctx->handle = pcap_create(ctx->device, ctx->errbuf);
    if (ctx->handle == NULL) {
        fprintf(stderr, "[capture] 无法创建设备 %s: %s\n",
                ctx->device, ctx->errbuf);
        return -1;
    }

    /* 设置快照长度 */
    if (pcap_set_snaplen(ctx->handle, ctx->snaplen) != 0) {
        fprintf(stderr, "[capture] 警告: 设置snaplen失败: %s\n",
                pcap_geterr(ctx->handle));
    }

    /* 设置混杂模式 */
    if (pcap_set_promisc(ctx->handle, ctx->promisc) != 0) {
        fprintf(stderr, "[capture] 警告: 设置混杂模式失败: %s\n",
                pcap_geterr(ctx->handle));
    }

    /* 设置读超时 */
    if (pcap_set_timeout(ctx->handle, ctx->timeout / 1000) != 0) {
        fprintf(stderr, "[capture] 警告: 设置超时失败: %s\n",
                pcap_geterr(ctx->handle));
    }

    /* 增大内核缓冲区，减少高流量下的丢包 (默认约2MB，设为8MB) */
    int buf_size = 8 * 1024 * 1024; /* 8MB */
    if (pcap_set_buffer_size(ctx->handle, buf_size) != 0) {
        fprintf(stderr, "[capture] 警告: 无法设置缓冲区大小: %s\n",
                pcap_geterr(ctx->handle));
    } else {
        printf("[capture] 内核缓冲区已设置为 %d MB\n", buf_size / (1024 * 1024));
    }

    /* 激活设备 */
    int ret = pcap_activate(ctx->handle);
    if (ret < 0) {
        fprintf(stderr, "[capture] 激活设备 %s 失败: %s\n",
                ctx->device, pcap_geterr(ctx->handle));
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        return -1;
    } else if (ret > 0) {
        /* 警告信息(非致命) */
        fprintf(stderr, "[capture] 警告: %s\n", pcap_geterr(ctx->handle));
    }

    /* 验证是否为以太网设备 */
    if (pcap_datalink(ctx->handle) != DLT_EN10MB) {
        fprintf(stderr, "[capture] 设备 %s 不是以太网类型\n", ctx->device);
        pcap_close(ctx->handle);
        ctx->handle = NULL;
        return -1;
    }

    printf("[capture] 已打开设备 %s (混杂模式: %s)\n",
           ctx->device, ctx->promisc ? "开" : "关");

    return 0;
}

void capture_set_callback(capture_ctx_t *ctx, packet_callback callback,
                          void *user_data)
{
    if (ctx == NULL) return;
    ctx->callback  = callback;
    ctx->user_data = user_data;
}

void capture_set_stats_callback(capture_ctx_t *ctx, stats_callback_t callback,
                                void *user_data)
{
    if (ctx == NULL) return;
    ctx->stats_callback  = callback;
    ctx->stats_user_data = user_data;
}

void capture_set_fast_mode(capture_ctx_t *ctx, int fast)
{
    if (ctx == NULL) return;
    ctx->fast_mode = fast;
    if (fast) {
        printf("[capture] 已启用快速模式(跳过完整协议解析)\n");
    }
}

int capture_loop(capture_ctx_t *ctx, int count)
{
    if (ctx == NULL || ctx->handle == NULL) {
        fprintf(stderr, "[capture] 设备未打开，请先调用 capture_open\n");
        return -1;
    }

    int captured = 0;
    struct timeval last_stats, now;
    gettimeofday(&last_stats, NULL);

    printf("[capture] 开始监听 %s ...\n", ctx->device);

    while (g_ctx != NULL) {
        /* 检查是否已抓够 */
        if (count > 0 && captured >= count) break;

        /* pcap_dispatch: 处理缓冲区中的包，无包时阻塞至超时(1秒) */
        int dispatch_cnt = (count > 0) ? (count - captured) : -1;
        int n = pcap_dispatch(ctx->handle, dispatch_cnt,
                              internal_callback, (u_char *)ctx);

        if (n == -1) {
            fprintf(stderr, "[capture] pcap_dispatch错误: %s\n",
                    pcap_geterr(ctx->handle));
            return -1;
        }
        if (n == -2) {
            /* pcap_breakloop 被调用(信号中断) */
            break;
        }
        captured += n;

        /* 检查是否需要每秒刷新统计 */
        gettimeofday(&now, NULL);
        if (now.tv_sec - last_stats.tv_sec >= 1) {
            if (ctx->stats_callback) {
                ctx->stats_callback(ctx->stats_user_data);
            }
            last_stats = now;
        }
    }

    printf("\n[capture] 抓包结束, 共捕获 %d 个数据包\n", captured);

    /* 打印内核级丢包统计 */
    struct pcap_stat ps;
    if (pcap_stats(ctx->handle, &ps) == 0) {
        printf("[capture] 内核统计: 收到 %u 包, 内核丢弃 %u 包, 接口丢弃 %u 包\n",
               ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
        if (ps.ps_recv > 0) {
            double drop_rate = (double)ps.ps_drop / (ps.ps_recv + ps.ps_drop) * 100.0;
            printf("[capture] 内核丢包率: %.2f%% (%u/%u)\n",
                   drop_rate, ps.ps_drop, ps.ps_recv + ps.ps_drop);
        }
    }

    return 0;
}

void capture_stop(capture_ctx_t *ctx)
{
    if (ctx && ctx->handle) {
        pcap_breakloop(ctx->handle);
    }
}

void capture_destroy(capture_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->handle) {
        pcap_close(ctx->handle);
        ctx->handle = NULL;
    }
    g_ctx = NULL;
}

void capture_list_devices(void)
{
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "[capture] 查找设备失败: %s\n", errbuf);
        return;
    }

    printf("可用网络设备:\n");
    printf("%-20s %s\n", "设备名", "描述");
    printf("----------------------------------------\n");
    for (d = alldevs; d != NULL; d = d->next) {
        printf("%-20s %s\n", d->name,
               d->description ? d->description : "(无描述)");
    }
    pcap_freealldevs(alldevs);
}

pcap_t *capture_get_handle(capture_ctx_t *ctx)
{
    return ctx ? ctx->handle : NULL;
}
