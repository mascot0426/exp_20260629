/**
 * @file    stats.c
 * @brief   流量统计实现 (Day7 时间维度统计版本)
 *
 * Day7 更新: 时间维度统计 + 每秒定时刷新
 *   - stats_init 中设置 enable_time_stats = 1
 *   - 新增 stats_print_brief() 每秒输出一行实时统计
 *   - 使用 \r 回车不换行实现原地刷新效果
 *   - 输出内容: elapsed时间 | 总包数 | 速率(pps/KB/s) | 协议分布概要
 *
 * 历史版本:
 *   - Day5: 按源/目的 IP 分别统计 (dst_ip_table)
 *   - Day4: 按协议类型统计流量 (字节数 + 占比)
 *   - Day3: 引入哈希表 (djb2 + 链表法)
 *   - Day2: 空壳版本 (协议维度基本计数)
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

/**
 * @brief 在哈希表中更新指定 IP 的统计 (内部辅助函数)
 *
 * 查找 IP 节点，存在则累加，不存在则新建 (头插法)。
 *
 * @param table   哈希表数组
 * @param ip_str  IP 地址字符串
 * @param len     数据包长度
 */
static void ip_table_update(ip_stats_node_t *table[], const char *ip_str, uint32_t len)
{
    if (ip_str == NULL || ip_str[0] == '\0') return;

    unsigned int idx = hash_ip(ip_str);
    ip_stats_node_t *node = table[idx];

    /* 查找是否已存在该 IP */
    while (node != NULL) {
        if (strcmp(node->ip_addr, ip_str) == 0) {
            node->packet_count++;
            node->byte_count += len;
            return;
        }
        node = node->next;
    }

    /* 不存在则新建节点 (头插法) */
    node = (ip_stats_node_t *)malloc(sizeof(ip_stats_node_t));
    if (node == NULL) return;
    strncpy(node->ip_addr, ip_str, IP_STR_LEN - 1);
    node->ip_addr[IP_STR_LEN - 1] = '\0';
    node->packet_count = 1;
    node->byte_count = len;
    node->next = table[idx];
    table[idx] = node;
}

void stats_init(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;
    memset(ctx, 0, sizeof(*ctx));
    gettimeofday(&ctx->start_time, NULL);
    ctx->enable_time_stats = 1;  /* Day7: 默认启用时间维度统计 */
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

    /* 按源 IP 哈希聚合统计 */
    ip_table_update(ctx->ip_table, pkt->src_ip, len);

    /* 按目的 IP 哈希聚合统计 (Day5 新增) */
    ip_table_update(ctx->dst_ip_table, pkt->dst_ip, len);
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

int stats_get_dst_ip_count(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return 0;
    int count = 0;
    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = ctx->dst_ip_table[i];
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

/**
 * @brief 打印 IP 哈希表内容 (内部辅助函数)
 * @param table   哈希表数组
 * @param label   段落标题
 */
static void ip_table_print(ip_stats_node_t *table[], const char *label, int count)
{
    printf("--------------------------------------------------------------\n");
    printf("%s (共 %d 个不同地址):\n", label, count);
    printf("  %-46s %10s %14s\n", "IP地址", "包数", "字节数");

    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = table[i];
        while (node != NULL) {
            printf("  %-46s %10lu %14lu\n",
                   node->ip_addr,
                   (unsigned long)node->packet_count,
                   (unsigned long)node->byte_count);
            node = node->next;
        }
    }
}

/**
 * @brief 打印简要统计 (每秒刷新, 抓包过程中实时调用)
 *
 * Day7 新增: 输出一行简要统计信息, 使用 \r 回车不换行实现原地刷新。
 * 在 capture_loop 的每秒回调中调用, 用户可实时看到抓包进度。
 *
 * 输出格式:
 *   [实时] 12s | 包:1234 速率:102.8pps/45.2KB/s | TCP:800 UDP:300 ICMP:50 ARP:20
 *
 * @param ctx 统计上下文
 */
void stats_print_brief(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;

    double pps  = (elapsed > 0) ? (ctx->proto_stats.total_packets / elapsed) : 0;
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

void stats_print(const stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    double elapsed = (now.tv_sec - ctx->start_time.tv_sec) +
                     (now.tv_usec - ctx->start_time.tv_usec) / 1000000.0;

    const proto_stats_t *s = &ctx->proto_stats;

    /* 计算速率 */
    double avg_pps  = (elapsed > 0) ? (s->total_packets / elapsed) : 0;
    double avg_kbps = (elapsed > 0) ? (s->total_bytes / 1024.0 / elapsed) : 0;
    double avg_mbps = avg_kbps / 1024.0;

    /* 清除实时刷新行 */
    printf("\r%80s\r", "");  /* 用空格覆盖之前的 brief 行 */
    printf("\n");

    /* ===== 报告标题 ===== */
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                      流量统计报告                          ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");

    /* ===== 统计摘要 ===== */
    printf("║  统计时长:   %-46.2f║\n", elapsed);
    printf("║  总数据包:   %-46lu║\n", (unsigned long)s->total_packets);
    printf("║  总字节数:   %-12lu (%.2f KB / %.2f MB)%16s║\n",
           (unsigned long)s->total_bytes,
           s->total_bytes / 1024.0,
           s->total_bytes / (1024.0 * 1024.0),
           "");

    if (elapsed > 0) {
        printf("║  平均速率:   %-12.2f pps / %.2f KB/s / %.2f Mb/s%9s║\n",
               avg_pps, avg_kbps, avg_mbps, "");
        printf("║  平均包长:   %-46.1f║\n",
               (double)s->total_bytes / (s->total_packets > 0 ? s->total_packets : 1));
    }

    /* ===== 链路层协议统计 ===== */
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  链路层协议分布                                            ║\n");
    printf("║  %-8s %10s %8s  %12s %8s     ║\n",
           "协议", "包数", "占比", "字节数", "占比");
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "IPv4", (unsigned long)s->ipv4_count, pct(s->ipv4_count, s->total_packets),
           (unsigned long)s->ipv4_bytes, pct(s->ipv4_bytes, s->total_bytes));
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "IPv6", (unsigned long)s->ipv6_count, pct(s->ipv6_count, s->total_packets),
           (unsigned long)s->ipv6_bytes, pct(s->ipv6_bytes, s->total_bytes));
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "ARP",  (unsigned long)s->arp_count,  pct(s->arp_count, s->total_packets),
           (unsigned long)s->arp_bytes,  pct(s->arp_bytes, s->total_bytes));
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "Other", (unsigned long)s->other_count, pct(s->other_count, s->total_packets),
           (unsigned long)s->other_bytes, pct(s->other_bytes, s->total_bytes));

    /* ===== 传输层协议统计 ===== */
    printf("╠════════════════════════════════════════════════════════════╣\n");
    printf("║  传输层协议分布                                            ║\n");
    printf("║  %-8s %10s %8s  %12s %8s     ║\n",
           "协议", "包数", "占比", "字节数", "占比");
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "TCP",  (unsigned long)s->tcp_count,  pct(s->tcp_count, s->total_packets),
           (unsigned long)s->tcp_bytes,  pct(s->tcp_bytes, s->total_bytes));
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "UDP",  (unsigned long)s->udp_count,  pct(s->udp_count, s->total_packets),
           (unsigned long)s->udp_bytes,  pct(s->udp_bytes, s->total_bytes));
    printf("║  %-8s %10lu %7.1f%%  %12lu %7.1f%%     ║\n",
           "ICMP", (unsigned long)s->icmp_count, pct(s->icmp_count, s->total_packets),
           (unsigned long)s->icmp_bytes, pct(s->icmp_bytes, s->total_bytes));

    printf("╚════════════════════════════════════════════════════════════╝\n");

    /* ===== 源 IP 地址维度统计 ===== */
    ip_table_print(ctx->ip_table, "源IP地址统计",
                   stats_get_ip_count(ctx));

    /* ===== 目的 IP 地址维度统计 ===== */
    ip_table_print(ctx->dst_ip_table, "目的IP地址统计",
                   stats_get_dst_ip_count(ctx));

    printf("==============================================================\n\n");
}

/**
 * @brief 释放哈希表所有节点 (内部辅助函数)
 * @param table 哈希表数组
 */
static void ip_table_destroy(ip_stats_node_t *table[])
{
    for (int i = 0; i < STATS_HASH_SIZE; i++) {
        ip_stats_node_t *node = table[i];
        while (node != NULL) {
            ip_stats_node_t *tmp = node;
            node = node->next;
            free(tmp);
        }
        table[i] = NULL;
    }
}

void stats_destroy(stats_ctx_t *ctx)
{
    if (ctx == NULL) return;

    /* 释放源 IP 哈希表 */
    ip_table_destroy(ctx->ip_table);

    /* 释放目的 IP 哈希表 (Day5 新增) */
    ip_table_destroy(ctx->dst_ip_table);
}
