/**
 * @file    pcap_io.h
 * @brief   PCAP文件读写接口定义 (Day6)
 *
 * 封装libpcap的savefile读写功能。
 *   - 写入: pcap_dump_open → pcap_dump → pcap_dump_close
 *   - 读取: pcap_open_offline → pcap_loop → pcap_close
 *
 * 参考: libpcap官方API (pcap_dump_open/pcap_dump/pcap_open_offline)
 */

#ifndef PCAP_IO_H
#define PCAP_IO_H

#include <pcap.h>
#include "packet.h"

/**
 * @brief PCAP文件写入上下文
 */
typedef struct {
    pcap_dumper_t *dumper;   /* libpcap dump句柄 */
    const char    *filename; /* 文件名 */
} pcap_save_ctx_t;

/* ===== 写入功能 ===== */

/**
 * @brief 打开PCAP文件用于写入
 * @param handle  pcap句柄(用于获取链路层类型)
 * @param filename 文件名
 * @return 写入上下文, NULL表示失败
 */
pcap_save_ctx_t *pcap_save_open(pcap_t *handle, const char *filename);

/**
 * @brief 将数据包写入文件(可作为pcap_loop回调直接使用)
 * @param user    用户数据(pcap_save_ctx_t指针)
 * @param header  数据包头
 * @param packet  原始数据包
 */
void pcap_save_packet(u_char *user, const struct pcap_pkthdr *header,
                      const u_char *packet);

/**
 * @brief 关闭并保存PCAP文件
 * @param ctx 写入上下文
 */
void pcap_save_close(pcap_save_ctx_t *ctx);

/* ===== 离线读取功能 ===== */

/**
 * @brief 打开PCAP文件用于离线读取
 * @param filename 文件名
 * @param errbuf   错误缓冲
 * @return pcap句柄, NULL表示失败
 */
pcap_t *pcap_replay_open(const char *filename, char *errbuf);

/**
 * @brief 从PCAP文件回放数据包
 * @param filename  文件名
 * @param filter_str 过滤表达式(NULL表示不过滤)
 * @param callback  数据包回调
 * @param user_data 用户数据
 * @return 0成功, -1失败
 */
int pcap_replay_loop(const char *filename, const char *filter_str,
                     pcap_handler callback, void *user_data);

#endif /* PCAP_IO_H */
