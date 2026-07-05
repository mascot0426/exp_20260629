/**
 * @file    capture.h
 * @brief   抓包引擎接口定义
 *
 * 封装libpcap抓包功能，支持实时抓包和离线文件读取。
 * 成员B的main.c通过此接口启动抓包。
 *
 * 架构说明:
 *   capture_init  -> capture_open -> [设置过滤器/存盘] -> capture_loop -> capture_destroy
 *   将"打开设备"和"启动循环"分离，使过滤器/存盘可以在循环前正确配置。
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include "packet.h"
#include <pcap.h>

/**
 * @brief 每秒统计回调函数类型
 * @param user_data 用户自定义数据
 */
typedef void (*stats_callback_t)(void *user_data);

/**
 * @brief 抓包上下文结构体
 */
typedef struct {
    pcap_t         *handle;        /* libpcap句柄 */
    char            device[256];   /* 网卡设备名 */
    int             promisc;       /* 是否混杂模式 */
    int             snaplen;       /* 快照长度 */
    int             timeout;       /* 读超时(ms) */
    packet_callback callback;      /* 数据包回调函数 */
    void           *user_data;     /* 回调用户数据 */
    stats_callback_t stats_callback; /* 每秒统计回调 */
    void           *stats_user_data;  /* 统计回调用户数据 */
    int             fast_mode;     /* 快速模式: 跳过完整解析,只做轻量统计 */
    char            errbuf[PCAP_ERRBUF_SIZE]; /* 错误缓冲 */
} capture_ctx_t;

/**
 * @brief 初始化抓包上下文
 * @param ctx    抓包上下文
 * @param device 网卡设备名(NULL则自动查找)
 * @param promisc 混杂模式(1开启/0关闭)
 */
void capture_init(capture_ctx_t *ctx, const char *device, int promisc);

/**
 * @brief 打开网卡设备(不启动抓包循环)
 *
 * 执行 pcap_open_live + 数据链路类型验证。
 * 打开后可通过 capture_get_handle 获取句柄，
 * 用于设置BPF过滤器和打开存盘文件。
 *
 * @param ctx 抓包上下文
 * @return 0成功, -1失败
 */
int capture_open(capture_ctx_t *ctx);

/**
 * @brief 设置数据包回调
 * @param ctx      抓包上下文
 * @param callback 回调函数
 * @param user_data 传递给回调的用户数据
 */
void capture_set_callback(capture_ctx_t *ctx, packet_callback callback, void *user_data);

/**
 * @brief 设置每秒统计回调
 * @param ctx       抓包上下文
 * @param callback  统计回调函数
 * @param user_data 统计回调用户数据
 */
void capture_set_stats_callback(capture_ctx_t *ctx, stats_callback_t callback, void *user_data);

/**
 * @brief 设置快速模式(跳过完整协议解析,仅做轻量统计)
 * @param ctx      抓包上下文
 * @param fast     1=启用快速模式, 0=正常模式
 */
void capture_set_fast_mode(capture_ctx_t *ctx, int fast);

/**
 * @brief 启动抓包循环(阻塞)
 *
 * 使用 pcap_dispatch 循环，每秒触发一次统计回调。
 * 需在 capture_open + 设置过滤器/存盘 之后调用。
 *
 * @param ctx   抓包上下文
 * @param count 抓包数量(-1为无限循环)
 * @return 0成功, 非0失败
 */
int capture_loop(capture_ctx_t *ctx, int count);

/**
 * @brief 中断抓包循环(用于信号处理)
 * @param ctx 抓包上下文
 */
void capture_stop(capture_ctx_t *ctx);

/**
 * @brief 清理抓包资源
 * @param ctx 抓包上下文
 */
void capture_destroy(capture_ctx_t *ctx);

/**
 * @brief 列出所有可用网络设备
 */
void capture_list_devices(void);

/**
 * @brief 获取libpcap句柄(供pcap_io模块使用)
 * @param ctx 抓包上下文
 * @return pcap_t指针
 */
pcap_t *capture_get_handle(capture_ctx_t *ctx);

#endif /* CAPTURE_H */
