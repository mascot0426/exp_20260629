/**
 * @file    stats.c
 * @brief   流量统计实现 (Day4 协议类型统计版本)
 *
 * Day4 更新: 完善按协议类型统计流量
 *   - proto_stats_t 增加各协议字节数字段
 *   - 新增协议名称映射函数 stats_ethertype_name() / stats_ipproto_name()
 *   - stats_update 中按协议更新字节数
 *   - stats_print 输出各协议包数、字节数和占比
 *
 * 后续迭代:
 *   - Day5: 按源/目的 IP 分别统计
 *   - Day7: 增加时间维度 + 每秒刷新
 *
 * 参考思路: mmahdi98/traffic_analyser (哈希表流聚合)
 */

#include "stats.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 简单字符串哈希函数 (djb2 算法)
 *
 * 将 IP 地址字符串映射到 [0, STATS_HASH_SIZE) 范围。
 * 哈希公式: hash = hash × 33 + c
 *
 * @param ip_str IP 地址字符串
 * @return 哈希值 (0 ~ STATS_HASH_SIZE-1)
 */
static unsigned int hash_ip(const char *ip_str)
{
    unsigned int hash = 5381;
    while (*ip_str) {
        hash = ((hash << 5) + hash) + *ip_str++;  /* hash * 33 + c */
    }
    return hash % STATS_HASH_SIZE;
}

/**
 * @brief 将 EtherType 转为可读协议名称
 * @param eth_type EtherType 值
 * @return 协议名称字符串
 */
const char *stats_ethertype_name(uint16_t eth_type)
{
    switch (eth_type) {
        case ETHERTYPE_IPV4: return "IPv4";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_ARP:  return "ARP";
        default:             return "Other";
    }
}

/**
 * @brief 将 IP 协议号转为可读协议名称
 * @param proto 协议号
 * @return 协议名称字符串
 */
const char *stats_ipproto_name(uint8_t proto)
{
    switch (proto) {
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default:           return "Other";
    }
}

void stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    gettimeofday(&ctx->start_time, NULL);
}

void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt)
{
    if (ctx == NULL || pkt == NULL) return;

    uint32_t len = pkt->cap_len;

    /* 更新总计数 */
    ctx->proto_stats.total_packets++;
    ctx->proto_stats.total_bytes += len;

    /* 按链路层协议类型统计包数和字节数 */
    switch (pkt->eth_type) {
        case ETHERTYPE_IPV4:
            ctx->proto_stats.ipv4_count++;
            ctx->proto_stats.ipv4_bytes += len;
            break;
        case ETHERTYPE_IPV6:
            ctx->proto_stats.ipv6_count++;
            ctx->proto_stats.ipv6_bytes += len;
            break;
        case ETHERTYPE_ARP:
            ctx->proto_stats.arp_count++;
            ctx->proto_stats.arp_bytes += len;
            break;
        default:
            ctx->proto_stats.other_count++;
            ctx->proto_stats.other_bytes += len;
            break;
    }

    /* 按网络层协议号统计包数和字节数 (仅 IPv4/IPv6 有上层协议) */
    if (pkt->eth_type == ETHERTYPE_IPV4 || pkt->eth_type == ETHERTYPE_IPV6) {
        switch (pkt->ip_proto) {
            case IPPROTO_TCP:
                ctx->proto_stats.tcp_count++;
                ctx->proto_stats.tcp_bytes += len;
                break;
            case IPPROTO_UDP:
                ctx->proto_stats.udp_count++;
                ctx->proto_stats.udp_bytes += len;
                break;
            case IPPROTO_ICMP:
                ctx->proto_stats.icmp_count++;
                ctx->proto_stats.icmp_bytes += len;
                break;
            default: break;
        }
    }

    /* 更新 IP 维度统计 (按源 IP 哈希聚合) */
    if (pkt->src_ip[0] != '\0') {
        unsigned int idx = hash_ip(pkt->src_ip);
        ip_stats_node_t *node = ctx->ip_table[idx];

        /* 查找是否已存在该 IP */
        while (node != NULL) {
            if (strcmp(node->ip_addr, pkt->src_ip) == 0) {
                node->packet_count++;
                node->byte_count += len;
                break;
            }
            node = node->next;
        }

        /* 不存在则新建节点 (头插法) */
        if (node == NULL) {
            node = (ip_stats_node_t *)malloc(sizeof(ip_stats_node_t));
            if (node == NULL) return;
            strncpy(node->ip_addr, pkt->src_ip, IP_STR_LEN - 1);
            node->ip_addr[IP_STR_LEN - 1] = '\0';
            node->packet_count = 1;
            node->byte_count = len;
            node->next = ctx->ip_table[idx];
            ctx->ip_table[idx] = node;
        }
    }

    /* TODO: Day5 起增加按目的 IP 统计 */
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

/**
 * @brief 计算占比百分比
 * @param part 部分值
 * @param total 总值
 * @return 百分比 (0.0 ~ 100.0)
 */
static double pct(uint64_t part, uint64_t total)
{
    if (total == 0) return 0.0;
    return (double)part * 100.0 / (double)total;
}

void stats_print(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;

    const proto_stats_t *s = &ctx->proto_stats;

    printf("\n");
    printf("==============================================================\n");
    printf("                      流量统计报告\n");
    printf("==============================================================\n");
    printf("统计时长:     %.2f 秒\n", elapsed);
    printf("总数据包:     %lu\n", (unsigned long)s->total_packets);
    printf("总字节数:     %lu (%.2f KB)\n",
           (unsigned long)s->total_bytes, s->total_bytes / 1024.0);

    if (elapsed > 0) {
        printf("平均速率:     %.2f pps, %.2f KB/s\n",
               s->total_packets / elapsed,
               s->total_bytes / 1024.0 / elapsed);
    }

    /* ===== 链路层协议统计 (包数 + 字节数 + 占比) ===== */
    printf("--------------------------------------------------------------\n");
    printf("链路层协议分布:\n");
    printf("  %-8s %10s %8s  %14s %8s\n", "协议", "包数", "占比", "字节数", "占比");
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "IPv4", (unsigned long)s->ipv4_count, pct(s->ipv4_count, s->total_packets),
           (unsigned long)s->ipv4_bytes, pct(s->ipv4_bytes, s->total_bytes));
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "IPv6", (unsigned long)s->ipv6_count, pct(s->ipv6_count, s->total_packets),
           (unsigned long)s->ipv6_bytes, pct(s->ipv6_bytes, s->total_bytes));
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "ARP",  (unsigned long)s->arp_count,  pct(s->arp_count, s->total_packets),
           (unsigned long)s->arp_bytes,  pct(s->arp_bytes, s->total_bytes));
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "Other", (unsigned long)s->other_count, pct(s->other_count, s->total_packets),
           (unsigned long)s->other_bytes, pct(s->other_bytes, s->total_bytes));

    /* ===== 传输层协议统计 (包数 + 字节数 + 占比) ===== */
    printf("--------------------------------------------------------------\n");
    printf("传输层协议分布:\n");
    printf("  %-8s %10s %8s  %14s %8s\n", "协议", "包数", "占比", "字节数", "占比");
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "TCP",  (unsigned long)s->tcp_count,  pct(s->tcp_count, s->total_packets),
           (unsigned long)s->tcp_bytes,  pct(s->tcp_bytes, s->total_bytes));
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "UDP",  (unsigned long)s->udp_count,  pct(s->udp_count, s->total_packets),
           (unsigned long)s->udp_bytes,  pct(s->udp_bytes, s->total_bytes));
    printf("  %-8s %10lu %7.1f%%  %14lu %7.1f%%\n",
           "ICMP", (unsigned long)s->icmp_count, pct(s->icmp_count, s->total_packets),
           (unsigned long)s->icmp_bytes, pct(s->icmp_bytes, s->total_bytes));

    /* ===== IP 地址维度统计 ===== */
    printf("--------------------------------------------------------------\n");
    printf("IP地址统计 (共 %d 个不同地址):\n", stats_get_ip_count(ctx));
    printf("  %-46s %10s %14s\n", "IP地址", "包数", "字节数");

    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = ctx->ip_table[i];
        while (node != NULL) {
            printf("  %-46s %10lu %14lu\n",
                   node->ip_addr,
                   (unsigned long)node->packet_count,
                   (unsigned long)node->byte_count);
            node = node->next;
        }
    }
    printf("==============================================================\n\n");

    /* TODO: Day7 起增加时间维度统计输出 */
}

void stats_destroy(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* 遍历哈希表，释放所有 IP 统计节点 */
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
