/**
 * @file    stats.h
 * @brief   流量统计模块接口定义
 *
 * 支持按协议类型/IP地址/时间三维统计流量。
 * 参考思路: mmahdi98/traffic_analyser (哈希表流聚合)
 */

#ifndef STATS_H
#define STATS_H

#include "packet.h"

/**
 * @brief 按协议类型统计
 */
typedef struct {
    uint64_t tcp_count;
    uint64_t udp_count;
    uint64_t icmp_count;
    uint64_t arp_count;
    uint64_t ipv4_count;
    uint64_t ipv6_count;
    uint64_t other_count;
    uint64_t total_packets;
    uint64_t total_bytes;
} proto_stats_t;

/**
 * @brief IP统计哈希表节点(链表解决冲突)
 */
typedef struct ip_stats_node {
    char     ip_addr[IP_STR_LEN];    /* IP地址 */
    uint64_t packet_count;           /* 包数 */
    uint64_t byte_count;             /* 字节数 */
    struct ip_stats_node *next;      /* 链表下一节点 */
} ip_stats_node_t;

/**
 * @brief 统计上下文
 */
typedef struct {
    proto_stats_t     proto_stats;                 /* 协议统计 */
    ip_stats_node_t  *ip_table[STATS_HASH_SIZE];   /* IP统计哈希表 */
    struct timeval     start_time;                  /* 统计开始时间 */
    int                enable_time_stats;           /* 是否启用时间维度统计 */
} stats_ctx_t;

/**
 * @brief 初始化统计上下文
 * @param ctx 统计上下文
 */
void stats_init(stats_ctx_t *ctx);

/**
 * @brief 更新统计(在数据包回调中调用)
 * @param ctx       统计上下文
 * @param pkt       解析后的数据包
 */
void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt);

/**
 * @brief 打印统计结果(完整报告, 抓包结束时调用)
 * @param ctx 统计上下文
 */
void stats_print(const stats_ctx_t *ctx);

/**
 * @brief 打印简要统计(每秒刷新, 抓包过程中实时调用)
 *
 * 输出一行简要统计信息, 包括已抓包数、速率、协议分布概要。
 * 使用 \r 回车不换行, 实现原地刷新效果。
 *
 * @param ctx 统计上下文
 */
void stats_print_brief(const stats_ctx_t *ctx);

/**
 * @brief 获取哈希表中的IP统计节点数
 * @param ctx 统计上下文
 * @return 不同IP地址数量
 */
int stats_get_ip_count(const stats_ctx_t *ctx);

/**
 * @brief 销毁统计上下文,释放内存
 * @param ctx 统计上下文
 */
void stats_destroy(stats_ctx_t *ctx);

#endif /* STATS_H */
