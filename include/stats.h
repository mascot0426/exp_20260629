/**
 * @file    stats.h
 * @brief   流量统计模块接口定义
 *
 * 支持按协议类型/IP地址/时间三维统计流量。
 *   - 协议维度: 按链路层/传输层协议分类统计包数和字节数
 *   - IP维度: 哈希表按源IP和目的IP分别聚合统计
 *   - 时间维度: 每秒定时刷新实时统计
 *
 * 参考思路: mmahdi98/traffic_analyser (哈希表流聚合)
 */

#ifndef STATS_H
#define STATS_H

#include "packet.h"
#include <sys/time.h>

/**
 * @brief 按协议类型统计 (包数 + 字节数)
 */
typedef struct {
    /* 包数统计 */
    uint64_t tcp_count;       /* TCP 包数 */
    uint64_t udp_count;       /* UDP 包数 */
    uint64_t icmp_count;      /* ICMP 包数 */
    uint64_t arp_count;       /* ARP 包数 */
    uint64_t ipv4_count;      /* IPv4 包数 */
    uint64_t ipv6_count;      /* IPv6 包数 */
    uint64_t other_count;     /* 其他协议包数 */
    uint64_t total_packets;   /* 总包数 */

    /* 字节数统计 */
    uint64_t tcp_bytes;       /* TCP 字节数 */
    uint64_t udp_bytes;       /* UDP 字节数 */
    uint64_t icmp_bytes;      /* ICMP 字节数 */
    uint64_t arp_bytes;       /* ARP 字节数 */
    uint64_t ipv4_bytes;      /* IPv4 字节数 */
    uint64_t ipv6_bytes;      /* IPv6 字节数 */
    uint64_t other_bytes;     /* 其他协议字节数 */
    uint64_t total_bytes;     /* 总字节数 */
} proto_stats_t;

/**
 * @brief IP 统计哈希表节点 (链表法解决冲突)
 */
typedef struct ip_stats_node {
    char     ip_addr[IP_STR_LEN];    /* IP 地址 */
    uint64_t packet_count;           /* 包数 */
    uint64_t byte_count;             /* 字节数 */
    struct ip_stats_node *next;      /* 链表下一节点 */
} ip_stats_node_t;

/**
 * @brief 统计上下文
 */
typedef struct {
    proto_stats_t     proto_stats;                   /* 协议统计 */
    ip_stats_node_t  *ip_table[STATS_HASH_SIZE];     /* 源 IP 统计哈希表 */
    ip_stats_node_t  *dst_ip_table[STATS_HASH_SIZE]; /* 目的 IP 统计哈希表 */
    struct timeval     start_time;                    /* 统计开始时间 */
    int                enable_time_stats;             /* 是否启用时间维度统计 */
} stats_ctx_t;

/* ===== 核心函数 ===== */

void stats_init(stats_ctx_t *ctx);
void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt);
void stats_print(const stats_ctx_t *ctx);
void stats_print_brief(const stats_ctx_t *ctx);
void stats_destroy(stats_ctx_t *ctx);

/* ===== 查询函数 ===== */

int stats_get_ip_count(const stats_ctx_t *ctx);
int stats_get_dst_ip_count(const stats_ctx_t *ctx);

/* ===== 协议名称映射 ===== */

const char *stats_ethertype_name(uint16_t eth_type);
const char *stats_ipproto_name(uint8_t proto);

#endif /* STATS_H */
