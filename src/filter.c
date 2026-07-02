/**
 * @file    filter.c
 * @brief   BPF过滤器实现
 *
 * 封装pcap_compile + pcap_setfilter,支持命令行传入过滤表达式。
 */

#include "filter.h"
#include <stdio.h>

int filter_compile(pcap_t *handle, struct bpf_program *fp,
                   const char *filter_str, bpf_u_int32 netmask)
{
    if (handle == NULL || fp == NULL || filter_str == NULL) {
        fprintf(stderr, "[filter] 参数错误\n");
        return -1;
    }

    if (pcap_compile(handle, fp, filter_str, 0, netmask) == -1) {
        fprintf(stderr, "[filter] 编译过滤表达式失败: %s\n", pcap_geterr(handle));
        fprintf(stderr, "[filter] 表达式: \"%s\"\n", filter_str);
        return -1;
    }

    printf("[filter] 过滤表达式已编译: \"%s\"\n", filter_str);
    return 0;
}

int filter_apply(pcap_t *handle, struct bpf_program *fp)
{
    if (handle == NULL || fp == NULL) {
        return -1;
    }

    if (pcap_setfilter(handle, fp) == -1) {
        fprintf(stderr, "[filter] 应用过滤器失败: %s\n", pcap_geterr(handle));
        return -1;
    }

    return 0;
}

void filter_free(struct bpf_program *fp)
{
    if (fp) {
        pcap_freecode(fp);
    }
}

void filter_print_examples(void)
{
    printf("\n常见BPF过滤表达式示例:\n");
    printf("============================================\n");
    printf("  ip                       只捕获IP包\n");
    printf("  tcp                      只捕获TCP包\n");
    printf("  udp                      只捕获UDP包\n");
    printf("  icmp                     只捕获ICMP包\n");
    printf("  arp                      只捕获ARP包\n");
    printf("  tcp port 80              捕获80端口TCP\n");
    printf("  udp port 53              捕获53端口UDP(DNS)\n");
    printf("  host 192.168.1.1         捕获指定IP流量\n");
    printf("  src host 192.168.1.1     捕获源IP流量\n");
    printf("  dst host 192.168.1.1     捕获目的IP流量\n");
    printf("  tcp port 80 and host 192.168.1.1  组合过滤\n");
    printf("  not port 22              排除SSH流量\n");
    printf("============================================\n\n");
}
