/**
 * @file    stats.c
 * @brief   流量统计实现 (Day2 空壳版本)
 *
 * 本版本为统计模块初始骨架:
 *   - stats_init:    清零 + 记录起始时间
 *   - stats_update:  仅按协议类型计数 (无 IP 哈希表)
 *   - stats_print:   打印基本协议分布
 *   - stats_destroy: 空实现 (Day2 无动态内存分配)
 *
 * 后续迭代:
 *   - Day3: 引入哈希表按 IP 聚合
 *   - Day7: 增加时间维度 + 每秒刷新
 */

#include "stats.h"
#include <stdio.h>
#include <string.h>

void stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    gettimeofday(&ctx->start_time, NULL);
}

void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt)
{
    if (ctx == NULL || pkt == NULL) return;

    /* 更新总计数 */
    ctx->proto_stats.total_packets++;
    ctx->proto_stats.total_bytes += pkt->cap_len;

    /* 按链路层协议类型计数 */
    switch (pkt->eth_type) {
        case ETHERTYPE_IPV4: ctx->proto_stats.ipv4_count++; break;
        case ETHERTYPE_IPV6: ctx->proto_stats.ipv6_count++; break;
        case ETHERTYPE_ARP:  ctx->proto_stats.arp_count++;  break;
        default:             ctx->proto_stats.other_count++; break;
    }

    /* 按网络层协议号计数 (仅 IPv4/IPv6 有上层协议) */
    if (pkt->eth_type == ETHERTYPE_IPV4 || pkt->eth_type == ETHERTYPE_IPV6) {
        switch (pkt->ip_proto) {
            case IPPROTO_TCP:  ctx->proto_stats.tcp_count++;  break;
            case IPPROTO_UDP:  ctx->proto_stats.udp_count++;  break;
            case IPPROTO_ICMP: ctx->proto_stats.icmp_count++; break;
            default: break;
        }
    }

    /* TODO: Day3 起增加 IP 维度哈希表统计 */
}

void stats_print(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;

    printf("\n");
    printf("============================================\n");
    printf("           流量统计报告\n");
    printf("============================================\n");
    printf("统计时长:     %.2f 秒\n", elapsed);
    printf("总数据包:     %lu\n", (unsigned long)ctx->proto_stats.total_packets);
    printf("总字节数:     %lu\n", (unsigned long)ctx->proto_stats.total_bytes);

    if (elapsed > 0) {
        printf("平均速率:     %.2f pps, %.2f KB/s\n",
               ctx->proto_stats.total_packets / elapsed,
               ctx->proto_stats.total_bytes / 1024.0 / elapsed);
    }

    printf("--------------------------------------------\n");
    printf("协议分布:\n");
    printf("  IPv4:     %lu\n", (unsigned long)ctx->proto_stats.ipv4_count);
    printf("  IPv6:     %lu\n", (unsigned long)ctx->proto_stats.ipv6_count);
    printf("  ARP:      %lu\n", (unsigned long)ctx->proto_stats.arp_count);
    printf("  其他:     %lu\n", (unsigned long)ctx->proto_stats.other_count);
    printf("  TCP:      %lu\n", (unsigned long)ctx->proto_stats.tcp_count);
    printf("  UDP:      %lu\n", (unsigned long)ctx->proto_stats.udp_count);
    printf("  ICMP:     %lu\n", (unsigned long)ctx->proto_stats.icmp_count);
    printf("============================================\n\n");

    /* TODO: Day3 起增加 IP 地址维度统计输出 */
}

void stats_destroy(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* Day2 版本无动态内存分配，销毁为空操作 */
    /* TODO: Day3 起释放 IP 哈希表内存 */
}
