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

/* TODO: 离线读取功能将在下一次提交中实现 */
