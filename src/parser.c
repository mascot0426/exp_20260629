/**
 * @file    parser.c
 * @brief   协议解析实现 (Eth -> IP -> TCP)
 *
 * 核心思想: 通过指针偏移逐层定位各层头部
 * 参考代码: sniffex.c 经典逐层偏移解析法
 *
 * 数据包偏移结构:
 *   +---------------+---------------+--------------+----------+
 *   | 以太网头 (14B) | IP头 (>=20B) | TCP/UDP(>=8B)  |  负载     |
 *   +---------------+---------------+--------------+----------+
 *   packet       +SIZE_ETHERNET  +size_ip      +size_tcp
 */

#include "parser.h"
#include <stdio.h>
#include <string.h>
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
int parse_ipv4(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_ip_t *ip = (const sniff_ip_t *)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;

    /* 有效性检查: IP头最小20字节 */
    if (size_ip < 20) {
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
int parse_ipv6(const uint8_t *packet, packet_info_t *pkt)
{
    const sniff_ipv6_t *ip6 = (const sniff_ipv6_t *)(packet + SIZE_ETHERNET);

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
            int size_ip = parse_ipv4(packet, pkt);
            if (size_ip == 0) { pkt->parsed_ok = 0; return; }
            pkt->parsed_ok = 1;

            const uint8_t *l4 = packet + SIZE_ETHERNET + size_ip;

            switch (pkt->ip_proto) {
                case IPPROTO_TCP: {
                    int size_tcp = parse_tcp(l4, pkt);
                    if (size_tcp == 0) return;
                    snprintf(pkt->proto_name, PROTO_NAME_LEN, "TCP");
                    const uint8_t *payload = l4 + size_tcp;
                    uint32_t payload_len = cap_len - SIZE_ETHERNET - size_ip - size_tcp;
                    pkt->payload = payload;
                    pkt->payload_len = payload_len;
                    break;
                }
                case IPPROTO_UDP: {
                    int size_udp = parse_udp(l4, pkt);
                    if (size_udp == 0) return;
                    snprintf(pkt->proto_name, PROTO_NAME_LEN, "UDP");
                    const uint8_t *payload = l4 + size_udp;
                    uint32_t payload_len = cap_len - SIZE_ETHERNET - size_ip - size_udp;
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
            int size_ip6 = parse_ipv6(packet, pkt);
            if (size_ip6 == 0) { pkt->parsed_ok = 0; return; }
            const uint8_t *l4 = packet + SIZE_ETHERNET + size_ip6;
            snprintf(pkt->proto_name, PROTO_NAME_LEN, "IPv6");

            if (pkt->ip_proto == IPPROTO_TCP) {
                parse_tcp(l4, pkt);
            }
            break;
        }

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

    char src_mac[18], dst_mac[18];
    mac_to_string(pkt->src_mac, src_mac, sizeof(src_mac));
    mac_to_string(pkt->dst_mac, dst_mac, sizeof(dst_mac));

    char flags_str[32] = "";
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
