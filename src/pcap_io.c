/**
 * @file    pcap_io.c
 * @brief   PCAP文件读写实现 (Day6)
 *
 * 写入: pcap_dump_open → pcap_dump → pcap_dump_close
 * 读取: pcap_open_offline → pcap_loop → pcap_close (后续追加)
 *
 * 参考: libpcap官方API文档
 */

#include "pcap_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ===== 写入功能 ===== */

pcap_save_ctx_t *pcap_save_open(pcap_t *handle, const char *filename)
{
    if (handle == NULL || filename == NULL) {
        fprintf(stderr, "[pcap_io] 参数错误\n");
        return NULL;
    }

    pcap_save_ctx_t *ctx = (pcap_save_ctx_t *)malloc(sizeof(pcap_save_ctx_t));
    if (ctx == NULL) {
        fprintf(stderr, "[pcap_io] 内存分配失败\n");
        return NULL;
    }

    ctx->dumper = pcap_dump_open(handle, filename);
    if (ctx->dumper == NULL) {
        fprintf(stderr, "[pcap_io] 打开保存文件失败: %s\n", pcap_geterr(handle));
        free(ctx);
        return NULL;
    }

    ctx->filename = filename;
    printf("[pcap_io] 已打开保存文件: %s\n", filename);
    return ctx;
}

void pcap_save_packet(u_char *user, const struct pcap_pkthdr *header,
                      const u_char *packet)
{
    pcap_save_ctx_t *ctx = (pcap_save_ctx_t *)user;
    if (ctx && ctx->dumper) {
        pcap_dump(user, header, packet);
    }
}

void pcap_save_close(pcap_save_ctx_t *ctx)
{
    if (ctx == NULL) return;
    if (ctx->dumper) {
        pcap_dump_close(ctx->dumper);
        ctx->dumper = NULL;
        printf("[pcap_io] 保存文件已关闭: %s\n", ctx->filename);
    }
    free(ctx);
}

/* ===== 离线读取功能 ===== */

pcap_t *pcap_replay_open(const char *filename, char *errbuf)
{
    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[pcap_io] 打开离线文件失败: %s\n", errbuf);
    } else {
        printf("[pcap_io] 已打开离线文件: %s\n", filename);
    }
    return handle;
}

int pcap_replay_loop(const char *filename, const char *filter_str,
                     pcap_handler callback, void *user_data)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    /* 打开离线文件 */
    pcap_t *handle = pcap_replay_open(filename, errbuf);
    if (handle == NULL) {
        return -1;
    }

    /* 设置过滤器(如果指定) */
    struct bpf_program fp;
    int has_filter = 0;
    if (filter_str != NULL) {
        bpf_u_int32 netmask = 0;  /* 离线文件用0作为netmask */
        if (pcap_compile(handle, &fp, filter_str, 1, netmask) == 0) {
            if (pcap_setfilter(handle, &fp) == 0) {
                has_filter = 1;
            } else {
                fprintf(stderr, "[pcap_io] 设置过滤器失败: %s\n", pcap_geterr(handle));
            }
        } else {
            fprintf(stderr, "[pcap_io] 编译过滤器失败: %s\n", pcap_geterr(handle));
        }
    }

    /* 读取数据包 */
    printf("[pcap_io] 开始回放...\n");
    int ret = pcap_loop(handle, -1, callback, (u_char *)user_data);

    if (ret == -1) {
        fprintf(stderr, "[pcap_io] 回放错误: %s\n", pcap_geterr(handle));
    }

    /* 清理 */
    if (has_filter) {
        pcap_freecode(&fp);
    }
    pcap_close(handle);
    printf("[pcap_io] 回放结束\n");
    return (ret == -1) ? -1 : 0;
}
