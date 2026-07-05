/**
 * @file    parser.h
 * @brief   协议解析接口定义
 *
 * 逐层解析数据包: Ethernet → IP → TCP/UDP/ICMP → DNS/HTTP
 * 参考实现: sniffex.c 经典逐层偏移解析法
 */

#ifndef PARSER_H
#define PARSER_H

#include "packet.h"

/**
 * @brief 解析数据包入口函数(由capture回调调用)
 *
 * 从原始数据包逐层解析，填充packet_info_t结构体。
 *
 * @param packet   原始数据包指针
 * @param cap_len  抓取长度
 * @param orig_len 原始长度
 * @param ts       时间戳
 * @param pkt      输出: 解析结果结构体
 */
void parse_packet(const uint8_t *packet, uint32_t cap_len,
                  uint32_t orig_len, struct timeval ts,
                  packet_info_t *pkt);

/* ===== 各层解析函数(内部使用,也可单独调用测试) ===== */

/**
 * @brief 解析以太网II帧头
 * @param packet 原始数据包
 * @param pkt    输出结构体
 */
void parse_ethernet(const uint8_t *packet, packet_info_t *pkt);

/**
 * @brief 解析IPv4头部
 * @param packet 原始数据包
 * @param pkt    输出结构体
 * @param cap_len 抓取长度(用于边界检查)
 * @return IP头部长度(字节), 0表示无效
 */
int parse_ipv4(const uint8_t *packet, packet_info_t *pkt, uint32_t cap_len);

/**
 * @brief 解析IPv6头部
 * @param packet 原始数据包(跳过以太网头后)
 * @param pkt    输出结构体
 * @param cap_len 抓取长度(用于边界检查)
 * @return IPv6头部长度(固定40字节), 0表示无效
 */
int parse_ipv6(const uint8_t *packet, packet_info_t *pkt, uint32_t cap_len);

/**
 * @brief 解析TCP头部
 * @param packet TCP头部起始指针
 * @param pkt    输出结构体
 * @return TCP头部长度(字节), 0表示无效
 */
int parse_tcp(const uint8_t *packet, packet_info_t *pkt);

/**
 * @brief 解析UDP头部
 * @param packet UDP头部起始指针
 * @param pkt    输出结构体
 * @return UDP头部长度(固定8字节), 0表示无效
 */
int parse_udp(const uint8_t *packet, packet_info_t *pkt);

/**
 * @brief 解析ICMP头部
 * @param packet ICMP头部起始指针
 * @param pkt    输出结构体
 */
void parse_icmp(const uint8_t *packet, packet_info_t *pkt);

/**
 * @brief 解析ARP头部
 * @param packet ARP头部起始指针
 * @param pkt    输出结构体
 */
void parse_arp(const uint8_t *packet, packet_info_t *pkt);

/**
 * @brief 解析DNS查询(应用层)
 * @param payload 负载数据
 * @param len     负载长度
 * @param pkt     输出结构体
 */
void parse_dns(const uint8_t *payload, uint32_t len, packet_info_t *pkt);

/**
 * @brief 识别HTTP请求/响应(应用层)
 * @param payload 负载数据
 * @param len     负载长度
 * @param pkt     输出结构体
 */
void parse_http(const uint8_t *payload, uint32_t len, packet_info_t *pkt);

/* ===== HTTP流跟踪与请求响应配对 ===== */

/**
 * @brief 初始化HTTP流跟踪表
 */
void http_flow_init(void);

/**
 * @brief 销毁HTTP流跟踪表，释放内存
 */
void http_flow_destroy(void);

/**
 * @brief 处理HTTP数据包，进行请求/响应配对
 * @param pkt 解析后的数据包(需已解析IP/TCP层)
 */
void http_flow_process(packet_info_t *pkt);

/**
 * @brief 打印所有已配对的HTTP请求/响应
 * @return 配对的数量
 */
int http_flow_print_pairs(void);

/**
 * @brief 获取已配对数量
 * @return 已成功配对的HTTP请求/响应数量
 */
int http_flow_get_pair_count(void);

/**
 * @brief 将TCP标志位转为可读字符串
 * @param flags TCP标志位
 * @param buf   输出缓冲
 * @param buflen 缓冲长度
 */
void tcp_flags_to_string(uint8_t flags, char *buf, int buflen);

/**
 * @brief 将MAC地址转为可读字符串
 * @param mac  MAC地址数组
 * @param buf  输出缓冲
 * @param buflen 缓冲长度
 */
void mac_to_string(const uint8_t *mac, char *buf, int buflen);

/**
 * @brief 打印数据包详细信息
 * @param pkt 解析后的数据包结构体
 */
void packet_print(const packet_info_t *pkt);

#endif /* PARSER_H */
