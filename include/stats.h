/**
 * @file    stats.h
 * @brief   流量统计模块接口定义 (Day5 源/目的IP统计版本)
 *
 * Day5 更新: 按源/目的 IP 分别统计
 *   - stats_ctx_t 增加目的 IP 哈希表 dst_ip_table
 *   - 新增 stats_get_dst_ip_count() 获取目的 IP 数量
 *   - 统计输出分源 IP 和目的 IP 两段显示
 *
 * 后续迭代计划:
 *   - Day7: 时间维度统计 + 每秒刷新 + 格式化输出
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

    /* 字节数统计 (Day4 新增) */
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
 *
 * 每个 IP 地址对应一个节点，记录该 IP 的包数和字节数。
 * 新节点插入到链表头部 (头插法)。
 */
typedef struct ip_stats_node {
    char     ip_addr[IP_STR_LEN];    /* IP 地址字符串 */
    uint64_t packet_count;           /* 包数 */
    uint64_t byte_count;             /* 字节数 */
    struct ip_stats_node *next;      /* 链表下一节点 */
} ip_stats_node_t;

/**
 * @brief 统计上下文
 *
 * Day5 更新: 增加目的 IP 哈希表，支持按源/目的 IP 分别统计。
 */
typedef struct {
    proto_stats_t     proto_stats;                 /* 协议统计 */
    ip_stats_node_t  *ip_table[STATS_HASH_SIZE];   /* 源 IP 统计哈希表 */
    ip_stats_node_t  *dst_ip_table[STATS_HASH_SIZE]; /* 目的 IP 统计哈希表 (Day5 新增) */
    struct timeval     start_time;                  /* 统计开始时间 */
} stats_ctx_t;

/**
 * @brief 初始化统计上下文
 * @param ctx 统计上下文
 */
void stats_init(stats_ctx_t *ctx);

/**
 * @brief 更新统计 (在数据包回调中调用)
 *
 * Day5 版本在 Day4 基础上，增加按目的 IP 的哈希表聚合统计。
 *
 * @param ctx 统计上下文
 * @param pkt 解析后的数据包
 */
void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt);

/**
 * @brief 打印统计结果 (抓包结束时调用)
 *
 * Day5 版本分源 IP 和目的 IP 两段显示统计。
 *
 * @param ctx 统计上下文
 */
void stats_print(const stats_ctx_t *ctx);

/**
 * @brief 获取源 IP 哈希表中的节点数
 * @param ctx 统计上下文
 * @return 不同源 IP 地址数量
 */
int stats_get_ip_count(const stats_ctx_t *ctx);

/**
 * @brief 获取目的 IP 哈希表中的节点数 (Day5 新增)
 * @param ctx 统计上下文
 * @return 不同目的 IP 地址数量
 */
int stats_get_dst_ip_count(const stats_ctx_t *ctx);

/**
 * @brief 将 EtherType 转为可读协议名称
 * @param eth_type EtherType 值
 * @return 协议名称字符串
 */
const char *stats_ethertype_name(uint16_t eth_type);

/**
 * @brief 将 IP 协议号转为可读协议名称
 * @param proto 协议号
 * @return 协议名称字符串
 */
const char *stats_ipproto_name(uint8_t proto);

/**
 * @brief 销毁统计上下文，释放哈希表内存
 * @param ctx 统计上下文
 */
void stats_destroy(stats_ctx_t *ctx);

#endif /* STATS_H */
