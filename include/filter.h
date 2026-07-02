/**
 * @file    filter.h
 * @brief   BPF过滤器接口定义
 *
 * 封装libpcap的BPF过滤功能,支持命令行传入过滤表达式。
 */

#ifndef FILTER_H
#define FILTER_H

#include <pcap.h>

/**
 * @brief 编译BPF过滤表达式
 * @param handle     pcap句柄
 * @param fp         编译后的BPF程序
 * @param filter_str 过滤表达式(如 "tcp port 80")
 * @param netmask    网络掩码
 * @return 0成功, -1失败
 */
int filter_compile(pcap_t *handle, struct bpf_program *fp,
                   const char *filter_str, bpf_u_int32 netmask);

/**
 * @brief 应用过滤器到抓包会话
 * @param handle pcap句柄
 * @param fp     编译后的BPF程序
 * @return 0成功, -1失败
 */
int filter_apply(pcap_t *handle, struct bpf_program *fp);

/**
 * @brief 释放过滤器资源
 * @param fp BPF程序
 */
void filter_free(struct bpf_program *fp);

/**
 * @brief 打印常见BPF过滤表达式示例
 */
void filter_print_examples(void);

#endif /* FILTER_H */
