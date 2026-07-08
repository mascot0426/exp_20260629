/**
 * @file    packet.h
 * @brief   共用数据包结构体与常量定义
 *
 * 本文件定义了全项目共用的数据包结构体 packet_info_t、回调函数类型、
 * 以及网络协议相关的常量宏。成员A和成员B通过此头文件进行接口对接。
 *
 * 设计参考: sniffex.c (libpcap 经典示例)
 *   - 以太网头大小硬编码为 14 字节，不用 sizeof 防止字节对齐
 *   - 用宏 IP_HL / TH_OFF 提取可变长头部
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <sys/time.h>
#include <netinet/in.h>   /* IPPROTO_ICMP/TCP/UDP 等协议号常量 */

/* ======================== 常量定义 ======================== */

#define SNAP_LEN        65535       /* 抓包快照长度 */
#define SIZE_ETHERNET   14          /* 以太网头大小(硬编码,不用sizeof) */
#define ETHER_ADDR_LEN  6           /* MAC地址长度 */

/* EtherType - 以太网帧类型 */
#define ETHERTYPE_IPV4  0x0800      /* IPv4 */
#define ETHERTYPE_IPV6  0x86DD      /* IPv6 */
#define ETHERTYPE_ARP   0x0806      /* ARP */

/* IP 协议号 - 已由系统头文件 <netinet/in.h> 定义，无需重复定义
 * (IPPROTO_ICMP=1, IPPROTO_TCP=6, IPPROTO_UDP=17) */

/* TCP 标志位 - 先 #undef 防止与系统头文件冲突，再重新定义 */
#ifdef TH_FIN
#undef TH_FIN
#endif
#define TH_FIN          0x01
#ifdef TH_SYN
#undef TH_SYN
#endif
#define TH_SYN          0x02
#ifdef TH_RST
#undef TH_RST
#endif
#define TH_RST          0x04
#ifdef TH_PUSH
#undef TH_PUSH
#endif
#define TH_PUSH         0x08
#ifdef TH_ACK
#undef TH_ACK
#endif
#define TH_ACK          0x10
#ifdef TH_URG
#undef TH_URG
#endif
#define TH_URG          0x20

/* 统计模块哈希表大小 */
#define STATS_HASH_SIZE 1024

/* 协议名称最大长度 */
#define PROTO_NAME_LEN  32

/* IP地址字符串最大长度 (支持IPv6) */
#define IP_STR_LEN      46

/* HTTP请求/响应最大内容长度 */
#define HTTP_CONTENT_MAX  256

/* MAC地址字符串长度 (XX:XX:XX:XX:XX:XX + null = 18) */
#define MAC_STR_LEN       18

/* TCP标志位字符串最大长度 (SYN ACK FIN RST PSH URG + null) */
#define TCP_FLAGS_STR_LEN 32

/* ======================== HTTP流跟踪结构 ======================== */

/**
 * @brief HTTP请求信息
 */
typedef struct {
    char     method[16];           /* 请求方法: GET/POST/PUT/DELETE */
    char     url[128];             /* 请求URL路径 */
    char     host[64];             /* Host头部 */
    char     user_agent[64];       /* User-Agent头部 */
    uint16_t status_code;          /* 响应状态码(仅响应有) */
    char     status_text[32];      /* 响应状态文本 */
    int      has_request;          /* 是否有请求数据 */
    int      has_response;         /* 是否有响应数据 */
    int      flow_paired;          /* 是否已完成请求/响应配对 */
} http_pair_info_t;

/**
 * @brief TCP流五元组键(用于HTTP请求响应配对)
 */
typedef struct {
    char     src_ip[IP_STR_LEN];
    uint16_t src_port;
    char     dst_ip[IP_STR_LEN];
    uint16_t dst_port;
    uint8_t  ip_proto;             /* IPPROTO_TCP */
} tcp_flow_key_t;

/**
 * @brief TCP流节点(HTTP请求响应配对用)
 */
typedef struct tcp_flow_node {
    tcp_flow_key_t       key;           /* 流标识 */
    http_pair_info_t     http_info;     /* HTTP配对信息 */
    struct tcp_flow_node *next;         /* 链表下一节点 */
} tcp_flow_node_t;

/* TCP流哈希表大小 */
#define FLOW_HASH_SIZE  256

/* ======================== 结构体定义 ======================== */

/**
 * @brief 以太网II帧头 (14字节)
 * @note  不用sizeof获取大小，硬编码SIZE_ETHERNET=14防止编译器对齐
 */
typedef struct {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];  /* 目的MAC地址 */
    uint8_t  ether_shost[ETHER_ADDR_LEN];  /* 源MAC地址 */
    uint16_t ether_type;                    /* 帧类型 */
} sniff_ethernet_t;

/**
 * @brief IPv4头部
 */
typedef struct {
    uint8_t  ip_vhl;                 /* 版本(高4位) | 头部长度(低4位,单位4字节) */
    uint8_t  ip_tos;                 /* 服务类型 */
    uint16_t ip_len;                 /* 总长度 */
    uint16_t ip_id;                  /* 标识 */
    uint16_t ip_off;                 /* 分片偏移 */
    uint8_t  ip_ttl;                 /* 生存时间 */
    uint8_t  ip_p;                   /* 协议号 */
    uint16_t ip_sum;                 /* 校验和 */
    uint32_t ip_src;                 /* 源IP地址(网络字节序) */
    uint32_t ip_dst;                 /* 目的IP地址(网络字节序) */
} sniff_ip_t;

/* 提取IP头部长度(字节) */
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
/* 提取IP版本号 */
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* IP分片标志 */
#define IP_RF 0x8000      /* 保留 */
#define IP_DF 0x4000      /* 不分片 */
#define IP_MF 0x2000      /* 还有分片 */
#define IP_OFFMASK 0x1fff /* 分片偏移掩码 */

/**
 * @brief IPv6头部 (固定40字节)
 */
typedef struct {
    uint32_t ip6_vtc_flow;   /* 版本 | 流量类别 | 流标签 */
    uint16_t ip6_plen;       /* 负载长度 */
    uint8_t  ip6_nxt;        /* 下一头部协议号 */
    uint8_t  ip6_hlim;       /* 跳数限制 */
    uint8_t  ip6_src[16];    /* 源地址 */
    uint8_t  ip6_dst[16];    /* 目的地址 */
} sniff_ipv6_t;

/**
 * @brief TCP头部
 */
typedef struct {
    uint16_t th_sport;       /* 源端口 */
    uint16_t th_dport;       /* 目的端口 */
    uint32_t th_seq;         /* 序列号 */
    uint32_t th_ack;         /* 确认号 */
    uint8_t  th_offx2;       /* 数据偏移(高4位) | 保留(低4位) */
    uint8_t  th_flags;       /* 标志位 */
    uint16_t th_win;         /* 窗口大小 */
    uint16_t th_sum;         /* 校验和 */
    uint16_t th_urp;         /* 紧急指针 */
} sniff_tcp_t;

/* 提取TCP数据偏移(头部长度单位: 4字节) */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

/**
 * @brief UDP头部
 */
typedef struct {
    uint16_t uh_sport;       /* 源端口 */
    uint16_t uh_dport;       /* 目的端口 */
    uint16_t uh_ulen;        /* UDP长度 */
    uint16_t uh_sum;         /* 校验和 */
} sniff_udp_t;

/**
 * @brief ICMP头部
 */
typedef struct {
    uint8_t  icmp_type;      /* 类型 */
    uint8_t  icmp_code;      /* 代码 */
    uint16_t icmp_cksum;     /* 校验和 */
    uint32_t icmp_rest;      /* 其余部分(因类型而异) */
} sniff_icmp_t;

/**
 * @brief ARP头部 (28字节)
 */
typedef struct {
    uint16_t arp_htype;      /* 硬件类型 */
    uint16_t arp_ptype;      /* 协议类型 */
    uint8_t  arp_hlen;       /* 硬件地址长度 */
    uint8_t  arp_plen;       /* 协议地址长度 */
    uint16_t arp_op;         /* 操作码: 1=请求, 2=应答 */
    uint8_t  arp_sha[6];     /* 发送方MAC */
    uint32_t arp_spa;        /* 发送方IP */
    uint8_t  arp_tha[6];     /* 目标MAC */
    uint32_t arp_tpa;        /* 目标IP */
} sniff_arp_t;

/* ARP操作码 */
#define ARP_REQUEST     1
#define ARP_REPLY       2

/**
 * @brief 统一数据包信息结构体 (成员A和成员B共用)
 *
 * 成员A的parser.c负责填充此结构体,
 * 成员B的stats.c和pcap_io.c通过此结构体获取解析结果。
 */
typedef struct {
    /* 原始数据 */
    const uint8_t *raw_data;      /* 指向原始数据包 */
    uint32_t       cap_len;       /* 抓取长度 */
    uint32_t       orig_len;      /* 原始长度 */
    struct timeval ts;            /* 时间戳 */

    /* 链路层 */
    uint8_t  src_mac[ETHER_ADDR_LEN];  /* 源MAC */
    uint8_t  dst_mac[ETHER_ADDR_LEN];  /* 目的MAC */
    uint16_t eth_type;                  /* EtherType */

    /* 网络层 */
    uint8_t  ip_proto;          /* 协议号(TCP/UDP/ICMP) */
    char     src_ip[IP_STR_LEN]; /* 源IP地址字符串 */
    char     dst_ip[IP_STR_LEN]; /* 目的IP地址字符串 */
    int      is_fragmented;     /* 是否IP分片 */

    /* 传输层 */
    uint16_t src_port;          /* 源端口 */
    uint16_t dst_port;          /* 目的端口 */
    uint8_t  tcp_flags;         /* TCP标志位 */

    /* 应用层 */
    char     proto_name[PROTO_NAME_LEN]; /* 协议名称 */
    const uint8_t *payload;     /* 应用层负载数据指针 */
    uint32_t      payload_len;  /* 负载长度 */

    /* HTTP解析增强 */
    http_pair_info_t http_info; /* HTTP请求/响应配对信息 */
    int              is_http_request;   /* 是否为HTTP请求方向 */
    int              flow_paired;     /* 是否已完成配对 */

    /* 解析状态 */
    int      parsed_ok;         /* 解析是否成功 */
} packet_info_t;

/**
 * @brief 数据包回调函数类型
 *
 * 成员A的capture.c在抓到包并解析后调用此回调,
 * 成员B的stats.c注册此回调来更新统计信息。
 *
 * @param pkt    解析后的数据包信息
 * @param user_data 用户自定义数据(如统计上下文)
 */
typedef void (*packet_callback)(const packet_info_t *pkt, void *user_data);

#endif /* PACKET_H */
