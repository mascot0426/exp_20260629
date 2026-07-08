/**
 * @file    parser.c
 * @brief   协议解析实现 (Eth → IP → TCP/UDP/ICMP → DNS/HTTP + ARP)
 *          增强版：支持HTTP请求/响应完整提取与配对
 *
 * 核心思想: 通过指针偏移逐层定位各层头部
 * 参考代码: sniffex.c 经典逐层偏移解析法
 *
 * 数据包偏移结构:
 *   ┌───────────────┬────────────┬──────────────┬──────────┐
 *   │ 以太网头 (14B) │ IP头 (≥20B) │ TCP/UDP(≥8B)  │  负载     │
 *   └───────────────┴────────────┴──────────────┴──────────┘
 *   packet       +SIZE_ETHERNET  +size_ip      +size_tcp
 */

#define _GNU_SOURCE  /* 启用 strcasestr 等 GNU 扩展 */

#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasestr */
#include <arpa/inet.h>
#include <netinet/in.h>

/* ===== MAC地址转字符串 ===== */
void mac_to_string(const uint8_t *mac, char *buf, int buflen)
{
    snprintf(buf, buflen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ===== TCP标志位转字符串 ===== */
void tcp_flags_to_string(uint8_t flags, char *buf, int buflen)
{
    int offset = 0;
    buf[0] = '\0';

    if (flags & TH_SYN)  offset += snprintf(buf + offset, buflen - offset, "SYN ");
    if (flags & TH_ACK)  offset += snprintf(buf + offset, buflen - offset, "ACK ");
    if (flags & TH_FIN)  offset += snprintf(buf + offset, buflen - offset, "FIN ");
    if (flags & TH_RST)  offset += snprintf(buf + offset, buflen - offset, "RST ");
    if (flags & TH_PUSH) offset += snprintf(buf + offset, buflen - offset, "PSH ");
    if (flags & TH_URG)  offset += snprintf(buf + offset, buflen - offset, "URG ");

    if (offset == 0) {
        snprintf(buf, buflen, "None");
    } else if (offset > 0 && buf[offset - 1] == ' ') {
        buf[offset - 1] = '\0'; /* 去掉末尾空格 */
    }
}

/* ===== 第一层: 以太网帧头解析 ===== */
void parse_ethernet(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_ethernet_t *eth = (const sniff_ethernet_t *)packet;

    memcpy(pkt->src_mac, eth->ether_shost, ETHER_ADDR_LEN);
    memcpy(pkt->dst_mac, eth->ether_dhost, ETHER_ADDR_LEN);
    pkt->eth_type = ntohs(eth->ether_type);
    pkt->raw_data = packet;
}

/* ===== 第二层: IPv4头部解析 ===== */
int parse_ipv4(const uint8_t *packet, packet_info_t *pkt, uint32_t cap_len)
{
    const sniff_ip_t *ip = (const sniff_ip_t *)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;

    /* 有效性检查: IP头最小20字节，最大60字节 */
    if (size_ip < 20 || size_ip > 60) {
        return 0;
    }

    /* 边界检查: 以太网头+IP头不超过抓取长度 */
    if (SIZE_ETHERNET + size_ip > cap_len) {
        return 0;
    }

    /* IP分片检测 */
    uint16_t frag_off = ntohs(ip->ip_off);
    pkt->is_fragmented = ((frag_off & IP_MF) || (frag_off & IP_OFFMASK)) ? 1 : 0;

    /* 转换IP地址为字符串 */
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip->ip_src;
    dst_addr.s_addr = ip->ip_dst;
    inet_ntop(AF_INET, &src_addr, pkt->src_ip, IP_STR_LEN);
    inet_ntop(AF_INET, &dst_addr, pkt->dst_ip, IP_STR_LEN);

    pkt->ip_proto = ip->ip_p;

    return size_ip;
}

/* ===== 第二层: IPv6头部解析 ===== */
int parse_ipv6(const uint8_t *packet, packet_info_t *pkt, uint32_t cap_len)
{
    const sniff_ipv6_t *ip6 = (const sniff_ipv6_t *)(packet + SIZE_ETHERNET);

    /* 边界检查: 以太网头+40字节IPv6头不超过抓取长度 */
    if (SIZE_ETHERNET + 40 > cap_len) {
        return 0;
    }

    /* IPv6地址转字符串 */
    inet_ntop(AF_INET6, ip6->ip6_src, pkt->src_ip, IP_STR_LEN);
    inet_ntop(AF_INET6, ip6->ip6_dst, pkt->dst_ip, IP_STR_LEN);

    pkt->ip_proto = ip6->ip6_nxt;

    return 40; /* IPv6头固定40字节 */
}

/* ===== 第三层: TCP头部解析 ===== */
int parse_tcp(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_tcp_t *tcp = (const sniff_tcp_t *)packet;
    int size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        return 0;
    }

    pkt->src_port   = ntohs(tcp->th_sport);
    pkt->dst_port   = ntohs(tcp->th_dport);
    pkt->tcp_flags  = tcp->th_flags;

    return size_tcp;
}

/* ===== 第三层: UDP头部解析 ===== */
int parse_udp(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_udp_t *udp = (const sniff_udp_t *)packet;

    pkt->src_port = ntohs(udp->uh_sport);
    pkt->dst_port = ntohs(udp->uh_dport);

    return 8; /* UDP头固定8字节 */
}

/* ===== 第三层: ICMP头部解析 ===== */
void parse_icmp(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_icmp_t *icmp = (const sniff_icmp_t *)packet;

    /* 根据类型码设置协议名称 */
    switch (icmp->icmp_type) {
        case 0:  snprintf(pkt->proto_name, PROTO_NAME_LEN, "ICMP Echo Reply"); break;
        case 8:  snprintf(pkt->proto_name, PROTO_NAME_LEN, "ICMP Echo Request"); break;
        case 3:  snprintf(pkt->proto_name, PROTO_NAME_LEN, "ICMP Dest Unreachable"); break;
        case 11: snprintf(pkt->proto_name, PROTO_NAME_LEN, "ICMP Time Exceeded"); break;
        default: snprintf(pkt->proto_name, PROTO_NAME_LEN, "ICMP type=%d", icmp->icmp_type); break;
    }
}

/* ===== ARP头部解析 ===== */
void parse_arp(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_arp_t *arp = (const sniff_arp_t *)(packet + SIZE_ETHERNET);
    uint16_t op = ntohs(arp->arp_op);

    /* 填入发送方/目标 MAC */
    memcpy(pkt->src_mac, arp->arp_sha, ETHER_ADDR_LEN);
    memcpy(pkt->dst_mac, arp->arp_tha, ETHER_ADDR_LEN);

    /* 填入发送方/目标 IP (ARP仅支持IPv4) */
    struct in_addr spa_addr, tpa_addr;
    spa_addr.s_addr = arp->arp_spa;
    tpa_addr.s_addr = arp->arp_tpa;
    inet_ntop(AF_INET, &spa_addr, pkt->src_ip, IP_STR_LEN);
    inet_ntop(AF_INET, &tpa_addr, pkt->dst_ip, IP_STR_LEN);

    if (op == ARP_REQUEST) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "ARP Request");
    } else if (op == ARP_REPLY) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "ARP Reply");
    } else {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "ARP op=%d", op);
    }
}

/* ===== 应用层: DNS解析 ===== */
void parse_dns(const uint8_t *payload, uint32_t len, packet_info_t *pkt)
{
    if (len < 12) return; /* DNS头最小12字节 */

    uint16_t qdcount = (payload[4] << 8) | payload[5];
    snprintf(pkt->proto_name, PROTO_NAME_LEN, "DNS (queries=%d)", qdcount);
}

/* ============================================================
 * 增强版 HTTP 解析：完整提取请求/响应信息
 * ============================================================ */

/**
 * @brief 从payload中提取HTTP请求方法、URL、Host等
 */
static void extract_http_request(const uint8_t *payload, uint32_t len,
                                  http_pair_info_t *info)
{
    if (len < 4) return;

    const char *data = (const char *)payload;
    const char *end = data + len;

    /* 提取方法 */
    if (strncmp(data, "GET ", 4) == 0) {
        snprintf(info->method, sizeof(info->method), "GET");
        data += 4;
    } else if (len >= 5 && strncmp(data, "POST ", 5) == 0) {
        snprintf(info->method, sizeof(info->method), "POST");
        data += 5;
    } else if (len >= 4 && strncmp(data, "PUT ", 4) == 0) {
        snprintf(info->method, sizeof(info->method), "PUT");
        data += 4;
    } else if (len >= 7 && strncmp(data, "DELETE ", 7) == 0) {
        snprintf(info->method, sizeof(info->method), "DELETE");
        data += 7;
    } else if (len >= 5 && strncmp(data, "HEAD ", 5) == 0) {
        snprintf(info->method, sizeof(info->method), "HEAD");
        data += 5;
    } else {
        snprintf(info->method, sizeof(info->method), "UNKNOWN");
        return;
    }

    /* 提取URL (从方法后到空格前) */
    const char *url_start = data;
    while (data < end && *data != ' ' && *data != '\r' && *data != '\n') data++;
    int url_len = data - url_start;
    if (url_len > 0 && url_len < (int)sizeof(info->url)) {
        memcpy(info->url, url_start, url_len);
        info->url[url_len] = '\0';
    }

    /* 提取Host头部 - 带长度限制的大小写不敏感搜索 */
    const char *host_ptr = NULL;
    const char *search = (const char *)payload;
    while (search + 6 <= end) {
        if (strncasecmp(search, "Host: ", 6) == 0) {
            host_ptr = search + 6;
            break;
        }
        search++;
    }
    if (host_ptr) {
        const char *host_end = host_ptr;
        while (host_end < end && *host_end != '\r' && *host_end != '\n') host_end++;
        int hlen = host_end - host_ptr;
        if (hlen > 0 && hlen < (int)sizeof(info->host)) {
            memcpy(info->host, host_ptr, hlen);
            info->host[hlen] = '\0';
        }
    }

    /* 提取User-Agent头部 - 带长度限制的大小写不敏感搜索 */
    const char *ua_ptr = NULL;
    search = (const char *)payload;
    while (search + 12 <= end) {
        if (strncasecmp(search, "User-Agent: ", 12) == 0) {
            ua_ptr = search + 12;
            break;
        }
        search++;
    }
    if (ua_ptr) {
        const char *ua_end = ua_ptr;
        while (ua_end < end && *ua_end != '\r' && *ua_end != '\n') ua_end++;
        int ualen = ua_end - ua_ptr;
        if (ualen > 0 && ualen < (int)sizeof(info->user_agent)) {
            memcpy(info->user_agent, ua_ptr, ualen);
            info->user_agent[ualen] = '\0';
        }
    }

    info->has_request = 1;
}

/**
 * @brief 从payload中提取HTTP响应状态码和状态文本
 */
static void extract_http_response(const uint8_t *payload, uint32_t len,
                                   http_pair_info_t *info)
{
    if (len < 12) return;

    const char *data = (const char *)payload;
    const char *end = data + len;

    /* 检查HTTP/1.x */
    if (strncmp(data, "HTTP/", 5) != 0) return;

    /* 跳过HTTP/1.x，找到状态码 */
    const char *p = data + 5;
    while (p < end && *p != ' ') p++;
    if (p < end && *p == ' ') p++;

    /* 提取3位状态码 */
    if (p + 3 > end) return; /* 不足3位 */
    int code = 0;
    if (p[0] >= '0' && p[0] <= '9') code = (p[0] - '0') * 100;
    if (p[1] >= '0' && p[1] <= '9') code += (p[1] - '0') * 10;
    if (p[2] >= '0' && p[2] <= '9') code += (p[2] - '0');
    info->status_code = (uint16_t)code;

    /* 提取状态文本 */
    p += 3;
    while (p < end && *p == ' ') p++;
    const char *text_end = p;
    while (text_end < end && *text_end != '\r' && *text_end != '\n') text_end++;
    int tlen = text_end - p;
    if (tlen > 0 && tlen < (int)sizeof(info->status_text)) {
        memcpy(info->status_text, p, tlen);
        info->status_text[tlen] = '\0';
    }

    info->has_response = 1;
}

/* ===== 应用层: HTTP识别与解析(增强版) ===== */
void parse_http(const uint8_t *payload, uint32_t len, packet_info_t *pkt)
{
    if (len < 4) return;

    memset(&pkt->http_info, 0, sizeof(pkt->http_info));

    /* 检查HTTP请求方法 */
    if (len >= 4 && memcmp(payload, "GET ", 4) == 0) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP GET");
        pkt->is_http_request = 1;
        extract_http_request(payload, len, &pkt->http_info);
    } else if (len >= 5 && memcmp(payload, "POST ", 5) == 0) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP POST");
        pkt->is_http_request = 1;
        extract_http_request(payload, len, &pkt->http_info);
    } else if (len >= 4 && memcmp(payload, "PUT ", 4) == 0) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP PUT");
        pkt->is_http_request = 1;
        extract_http_request(payload, len, &pkt->http_info);
    } else if (len >= 7 && memcmp(payload, "DELETE ", 7) == 0) {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP DELETE");
        pkt->is_http_request = 1;
        extract_http_request(payload, len, &pkt->http_info);
    } else if (len >= 5 && memcmp(payload, "HTTP/", 5) == 0) {
        /* HTTP响应 */
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP Response");
        pkt->is_http_request = 0;
        extract_http_response(payload, len, &pkt->http_info);
    } else {
        snprintf(pkt->proto_name, PROTO_NAME_LEN, "HTTP");
    }
}

/* ============================================================
 * HTTP流跟踪与请求/响应配对
 * ============================================================ */

static tcp_flow_node_t *g_flow_table[FLOW_HASH_SIZE] = {NULL};
static int g_http_pair_count = 0;

/* 流键哈希 - 对称哈希，确保正向和反向流产生相同的哈希值 */
static unsigned int flow_hash(const tcp_flow_key_t *key)
{
    unsigned int hash1 = 5381;
    unsigned int hash2 = 5381;
    const char *p;

    /* 对 src_ip 和 dst_ip 分别计算哈希 */
    p = key->src_ip;
    while (*p) hash1 = ((hash1 << 5) + hash1) + *p++;
    p = key->dst_ip;
    while (*p) hash2 = ((hash2 << 5) + hash2) + *p++;

    /* 对 src_port 和 dst_port 分别计算哈希 */
    hash1 = ((hash1 << 5) + hash1) + key->src_port;
    hash2 = ((hash2 << 5) + hash2) + key->dst_port;

    /* 相加以实现对称性: hash(A,B) == hash(B,A) */
    return (hash1 + hash2) % FLOW_HASH_SIZE;
}

/* 比较两个流键是否匹配(正向或反向) */
static int flow_key_match(const tcp_flow_key_t *a, const tcp_flow_key_t *b)
{
    /* 正向匹配 */
    if (strcmp(a->src_ip, b->src_ip) == 0 && a->src_port == b->src_port &&
        strcmp(a->dst_ip, b->dst_ip) == 0 && a->dst_port == b->dst_port) {
        return 1;
    }
    /* 反向匹配 */
    if (strcmp(a->src_ip, b->dst_ip) == 0 && a->src_port == b->dst_port &&
        strcmp(a->dst_ip, b->src_ip) == 0 && a->dst_port == b->src_port) {
        return 1;
    }
    return 0;
}

void http_flow_init(void)
{
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        g_flow_table[i] = NULL;
    }
    g_http_pair_count = 0;
}

void http_flow_destroy(void)
{
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        tcp_flow_node_t *node = g_flow_table[i];
        while (node != NULL) {
            tcp_flow_node_t *tmp = node;
            node = node->next;
            free(tmp);
        }
        g_flow_table[i] = NULL;
    }
    g_http_pair_count = 0;
}

void http_flow_process(const packet_info_t *pkt)
{
    if (pkt == NULL || pkt->ip_proto != IPPROTO_TCP) return;
    if (pkt->src_port != 80 && pkt->dst_port != 80) return;

    /* 构造流键 */
    tcp_flow_key_t key;
    memset(&key, 0, sizeof(key));
    strncpy(key.src_ip, pkt->src_ip, IP_STR_LEN - 1);
    key.src_port = pkt->src_port;
    strncpy(key.dst_ip, pkt->dst_ip, IP_STR_LEN - 1);
    key.dst_port = pkt->dst_port;
    key.ip_proto = pkt->ip_proto;

    unsigned int idx = flow_hash(&key);
    tcp_flow_node_t *node = g_flow_table[idx];

    /* 查找现有流 */
    while (node != NULL) {
        if (flow_key_match(&node->key, &key)) {
            /* 找到匹配流，更新HTTP信息 */
            if (pkt->is_http_request && pkt->http_info.has_request) {
                /* 客户端请求方向 */
                if (!node->http_info.has_request) {
                    memcpy(&node->http_info, &pkt->http_info, sizeof(http_pair_info_t));
                    node->http_info.has_request = 1;
                }
            } else if (!pkt->is_http_request && pkt->http_info.has_response) {
                /* 服务器响应方向 */
                if (!node->http_info.has_response) {
                    node->http_info.status_code = pkt->http_info.status_code;
                    snprintf(node->http_info.status_text, sizeof(node->http_info.status_text),
                             "%s", pkt->http_info.status_text);
                    node->http_info.has_response = 1;
                }
            }

            /* 标记是否已配对 */
            if (node->http_info.has_request && node->http_info.has_response &&
                !node->http_info.flow_paired) {
                node->http_info.flow_paired = 1;
                g_http_pair_count++;
            }
            pkt->flow_paired = node->http_info.flow_paired;
            if (pkt->flow_paired) {
                memcpy(&pkt->http_info, &node->http_info, sizeof(http_pair_info_t));
            }
            return;
        }
        node = node->next;
    }

    /* 未找到，新建流节点 */
    node = (tcp_flow_node_t *)malloc(sizeof(tcp_flow_node_t));
    if (node == NULL) return;

    memset(node, 0, sizeof(tcp_flow_node_t));
    memcpy(&node->key, &key, sizeof(tcp_flow_key_t));

    if (pkt->is_http_request && pkt->http_info.has_request) {
        memcpy(&node->http_info, &pkt->http_info, sizeof(http_pair_info_t));
    } else if (!pkt->is_http_request && pkt->http_info.has_response) {
        node->http_info.status_code = pkt->http_info.status_code;
        snprintf(node->http_info.status_text, sizeof(node->http_info.status_text),
                 "%s", pkt->http_info.status_text);
        node->http_info.has_response = 1;
    }

    node->next = g_flow_table[idx];
    g_flow_table[idx] = node;
}

int http_flow_print_pairs(void)
{
    if (g_http_pair_count == 0) {
        printf("\n[HTTP] 未发现已配对的请求/响应\n");
        return 0;
    }

    printf("\n========================================\n");
    printf("        HTTP 请求/响应配对报告\n");
    printf("========================================\n");

    int printed = 0;
    for (int i = 0; i < FLOW_HASH_SIZE; i++) {
        tcp_flow_node_t *node = g_flow_table[i];
        while (node != NULL) {
            if (node->http_info.flow_paired) {
                printf("\n--- 配对 #%d ---\n", ++printed);
                printf("  请求: %s %s\n",
                       node->http_info.method, node->http_info.url);
                if (node->http_info.host[0]) {
                    printf("  Host: %s\n", node->http_info.host);
                }
                printf("  响应: %d %s\n",
                       node->http_info.status_code,
                       node->http_info.status_text);
            }
            node = node->next;
        }
    }
    printf("\n========================================\n");
    printf("共发现 %d 对 HTTP 请求/响应\n", printed);
    printf("========================================\n");
    return printed;
}

int http_flow_get_pair_count(void)
{
    return g_http_pair_count;
}

/* ===== 主入口: 逐层解析数据包 ===== */
void parse_packet(const uint8_t *packet, uint32_t cap_len,
                  uint32_t orig_len, struct timeval ts,
                  packet_info_t *pkt)
{
    if (packet == NULL || pkt == NULL || cap_len < SIZE_ETHERNET) {
        if (pkt) pkt->parsed_ok = 0;
        return;
    }

    memset(pkt, 0, sizeof(*pkt));
    pkt->raw_data = packet;
    pkt->cap_len  = cap_len;
    pkt->orig_len = orig_len;
    pkt->ts       = ts;
    pkt->parsed_ok = 1;

    /* 第一层: 以太网 */
    parse_ethernet(packet, pkt);

    /* 根据EtherType分流 */
    switch (pkt->eth_type) {
        case ETHERTYPE_IPV4: {
            int size_ip = parse_ipv4(packet, pkt, cap_len);
            if (size_ip == 0) { pkt->parsed_ok = 0; return; }
            pkt->parsed_ok = 1;

            const uint8_t *l4 = packet + SIZE_ETHERNET + size_ip;

            switch (pkt->ip_proto) {
                case IPPROTO_TCP: {
                    int size_tcp = parse_tcp(l4, pkt);
                    if (size_tcp == 0) return;
                    snprintf(pkt->proto_name, PROTO_NAME_LEN, "TCP");
                    /* 应用层识别 */
                    const uint8_t *payload = l4 + size_tcp;
                    uint32_t payload_len = cap_len - SIZE_ETHERNET - size_ip - size_tcp;
                    if (pkt->src_port == 80 || pkt->dst_port == 80) {
                        parse_http(payload, payload_len, pkt);
                        /* HTTP流配对处理 */
                        http_flow_process(pkt);
                    }
                    pkt->payload = payload;
                    pkt->payload_len = payload_len;
                    break;
                }
                case IPPROTO_UDP: {
                    int size_udp = parse_udp(l4, pkt);
                    if (size_udp == 0) return;
                    snprintf(pkt->proto_name, PROTO_NAME_LEN, "UDP");
                    /* DNS识别(端口53) */
                    const uint8_t *payload = l4 + size_udp;
                    uint32_t payload_len = cap_len - SIZE_ETHERNET - size_ip - size_udp;
                    if (pkt->src_port == 53 || pkt->dst_port == 53) {
                        parse_dns(payload, payload_len, pkt);
                    }
                    pkt->payload = payload;
                    pkt->payload_len = payload_len;
                    break;
                }
                case IPPROTO_ICMP:
                    parse_icmp(l4, pkt);
                    break;
                default:
                    snprintf(pkt->proto_name, PROTO_NAME_LEN, "IP proto=%d", pkt->ip_proto);
                    break;
            }
            break;
        }

        case ETHERTYPE_IPV6: {
            int size_ip6 = parse_ipv6(packet, pkt, cap_len);
            if (size_ip6 == 0) { pkt->parsed_ok = 0; return; }
            const uint8_t *l4 = packet + SIZE_ETHERNET + size_ip6;
            snprintf(pkt->proto_name, PROTO_NAME_LEN, "IPv6");

            if (pkt->ip_proto == IPPROTO_TCP) {
                parse_tcp(l4, pkt);
            } else if (pkt->ip_proto == IPPROTO_UDP) {
                parse_udp(l4, pkt);
            } else if (pkt->ip_proto == IPPROTO_ICMP) {
                parse_icmp(l4, pkt);
            }
            break;
        }

        case ETHERTYPE_ARP:
            parse_arp(packet, pkt);
            break;

        default:
            snprintf(pkt->proto_name, PROTO_NAME_LEN, "EtherType=0x%04x", pkt->eth_type);
            break;
    }
}

/* ===== 打印数据包信息 ===== */
void packet_print(const packet_info_t *pkt)
{
    if (!pkt || !pkt->parsed_ok) {
        printf("[无效数据包]\n");
        return;
    }

    char src_mac[MAC_STR_LEN], dst_mac[MAC_STR_LEN];
    mac_to_string(pkt->src_mac, src_mac, sizeof(src_mac));
    mac_to_string(pkt->dst_mac, dst_mac, sizeof(dst_mac));

    char flags_str[TCP_FLAGS_STR_LEN] = "";
    if (pkt->tcp_flags) {
        tcp_flags_to_string(pkt->tcp_flags, flags_str, sizeof(flags_str));
    }

    printf("[%ld.%06ld] %s | ", pkt->ts.tv_sec, pkt->ts.tv_usec, pkt->proto_name);

    if (pkt->src_ip[0]) {
        printf("%s", pkt->src_ip);
        if (pkt->src_port) printf(":%d", pkt->src_port);
        printf(" -> ");
        printf("%s", pkt->dst_ip);
        if (pkt->dst_port) printf(":%d", pkt->dst_port);
    } else {
        printf("%s -> %s", src_mac, dst_mac);
    }

    if (flags_str[0]) printf(" [%s]", flags_str);
    if (pkt->is_fragmented) printf(" [Fragmented]");
    printf(" (%u bytes)\n", pkt->cap_len);
}
