/**
 * @file    stats.h
 * @brief   流量统计模块接口定义 (Day2 空壳版本)
 *
 * 本版本为统计模块初始骨架，仅实现协议维度的基本计数与打印。
 * 后续迭代计划:
 *   - Day3: 改用哈希表存储 IP 维度统计
 *   - Day4: 完善按协议类型统计
 *   - Day5: 按源/目的 IP 统计
 *   - Day7: 时间维度统计 + 每秒刷新 + 格式化输出
 */

#ifndef STATS_H
#define STATS_H

#include "packet.h"
#include <sys/time.h>

/**
 * @brief 按协议类型统计
 */
typedef struct {
    uint64_t tcp_count;       /* TCP 包数 */
    uint64_t udp_count;       /* UDP 包数 */
    uint64_t icmp_count;      /* ICMP 包数 */
    uint64_t arp_count;       /* ARP 包数 */
    uint64_t ipv4_count;      /* IPv4 包数 */
    uint64_t ipv6_count;      /* IPv6 包数 */
    uint64_t other_count;     /* 其他协议包数 */
    uint64_t total_packets;   /* 总包数 */
    uint64_t total_bytes;     /* 总字节数 */
} proto_stats_t;

/**
 * @brief 统计上下文
 *
 * Day2 版本仅包含协议维度统计和起始时间。
 * Day3 起将增加 IP 哈希表等字段。
 */
typedef struct {
    proto_stats_t  proto_stats;   /* 协议统计 */
    struct timeval start_time;    /* 统计开始时间 */
} stats_ctx_t;

/**
 * @brief 初始化统计上下文
 * @param ctx 统计上下文
 */
void stats_init(stats_ctx_t *ctx);

/**
 * @brief 更新统计 (在数据包回调中调用)
 * @param ctx 统计上下文
 * @param pkt 解析后的数据包
 */
void stats_update(stats_ctx_t *ctx, const packet_info_t *pkt);

/**
 * @brief 打印统计结果 (抓包结束时调用)
 * @param ctx 统计上下文
 */
void stats_print(const stats_ctx_t *ctx);

/**
 * @brief 销毁统计上下文，释放内存
 * @param ctx 统计上下文
 */
void stats_destroy(stats_ctx_t *ctx);

#endif /* STATS_H */
