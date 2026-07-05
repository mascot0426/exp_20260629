/**
 * @file    stats.c
 * @brief   流量统计实现 (协议维度 + IP维度 + 时间维度)
 *
 * 使用哈希表按IP地址聚合统计,按协议类型分类计数。
 * 参考思路: mmahdi98/traffic_analyser (哈希表流聚合)
 */

#include "stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* 简单字符串哈希函数 */
static unsigned int hash_ip(const char *ip_str)
{
    unsigned int hash = 5381;
    while (*ip_str) {
        hash = ((hash << 5) + hash) + *ip_str++;
    }
    return hash % STATS_HASH_SIZE;
}

void stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    gettimeofday(&ctx->start_time, NULL);
    ctx->enable_time_stats = 1;
}

void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt)
{
    if (ctx == NULL || pkt == NULL) return;

    /* 更新协议维度统计 */
    ctx->proto_stats.total_packets++;
    ctx->proto_stats.total_bytes += pkt->cap_len;

    switch (pkt->eth_type) {
        case ETHERTYPE_IPV4: ctx->proto_stats.ipv4_count++; break;
        case ETHERTYPE_IPV6: ctx->proto_stats.ipv6_count++; break;
        case ETHERTYPE_ARP:  ctx->proto_stats.arp_count++;  break;
        default:             ctx->proto_stats.other_count++; break;
    }

    if (pkt->eth_type == ETHERTYPE_IPV4 || pkt->eth_type == ETHERTYPE_IPV6) {
        switch (pkt->ip_proto) {
            case IPPROTO_TCP:  ctx->proto_stats.tcp_count++;  break;
            case IPPROTO_UDP:  ctx->proto_stats.udp_count++;  break;
            case IPPROTO_ICMP: ctx->proto_stats.icmp_count++; break;
            default: break;
        }
    }

    /* 更新IP维度统计(仅IPv4/IPv6有IP地址) */
    if (pkt->src_ip[0] != '\0') {
        unsigned int idx = hash_ip(pkt->src_ip);
        ip_stats_node_t *node = ctx->ip_table[idx];

        /* 查找是否已存在 */
        while (node != NULL) {
            if (strcmp(node->ip_addr, pkt->src_ip) == 0) {
                node->packet_count++;
                node->byte_count += pkt->cap_len;
                break;
            }
            node = node->next;
        }

        /* 不存在则新建 */
        if (node == NULL) {
            node = (ip_stats_node_t *)malloc(sizeof(ip_stats_node_t));
            if (node == NULL) return;
            strncpy(node->ip_addr, pkt->src_ip, IP_STR_LEN - 1);
            node->ip_addr[IP_STR_LEN - 1] = '\0';
            node->packet_count = 1;
            node->byte_count = pkt->cap_len;
            node->next = ctx->ip_table[idx];
            ctx->ip_table[idx] = node;
        }
    }
}

int stats_get_ip_count(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    int count = 0;
    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = ctx->ip_table[i];
        while (node != NULL) {
            count++;
            node = node->next;
        }
    }
    return count;
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
    printf("总数据包:     %lu\n", ctx->proto_stats.total_packets);
    printf("总字节数:     %lu\n", ctx->proto_stats.total_bytes);

    if (elapsed > 0) {
        printf("平均速率:     %.2f pps, %.2f KB/s\n",
               ctx->proto_stats.total_packets / elapsed,
               ctx->proto_stats.total_bytes / 1024.0 / elapsed);
    }

    printf("--------------------------------------------\n");
    printf("协议分布:\n");
    printf("  IPv4:     %lu\n", ctx->proto_stats.ipv4_count);
    printf("  IPv6:     %lu\n", ctx->proto_stats.ipv6_count);
    printf("  ARP:      %lu\n", ctx->proto_stats.arp_count);
    printf("  其他:     %lu\n", ctx->proto_stats.other_count);
    printf("  TCP:      %lu\n", ctx->proto_stats.tcp_count);
    printf("  UDP:      %lu\n", ctx->proto_stats.udp_count);
    printf("  ICMP:     %lu\n", ctx->proto_stats.icmp_count);

    printf("--------------------------------------------\n");
    printf("IP地址统计 (共 %d 个不同地址):\n", stats_get_ip_count(ctx));
    printf("  %-46s %10s %12s\n", "IP地址", "包数", "字节数");

    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = ctx->ip_table[i];
        while (node != NULL) {
            printf("  %-46s %10lu %12lu\n",
                   node->ip_addr, node->packet_count, node->byte_count);
            node = node->next;
        }
    }
    printf("============================================\n\n");
}

void stats_print_brief(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;

    double pps = (elapsed > 0) ? (ctx->proto_stats.total_packets / elapsed) : 0;
    double kbps = (elapsed > 0) ? (ctx->proto_stats.total_bytes / 1024.0 / elapsed) : 0;

    /* 使用 \r 回车实现原地刷新 */
    printf("\r[实时] %lus | 包:%lu 速率:%.1fpps/%.1fKB/s | TCP:%lu UDP:%lu ICMP:%lu ARP:%lu",
           (unsigned long)elapsed,
           (unsigned long)ctx->proto_stats.total_packets,
           pps, kbps,
           (unsigned long)ctx->proto_stats.tcp_count,
           (unsigned long)ctx->proto_stats.udp_count,
           (unsigned long)ctx->proto_stats.icmp_count,
           (unsigned long)ctx->proto_stats.arp_count);
    fflush(stdout);
}

void stats_destroy(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = ctx->ip_table[i];
        while (node != NULL) {
            ip_stats_node_t *tmp = node;
            node = node->next;
            free(tmp);
        }
        ctx->ip_table[i] = NULL;
    }
}
