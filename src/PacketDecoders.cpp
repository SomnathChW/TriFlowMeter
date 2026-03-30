// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "PacketDecoders.h"

#include <cstring>
#include <string>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

struct ip {
#if defined(_MSC_VER)
    u_char ip_hl : 4;
    u_char ip_v : 4;
#else
    u_char ip_hl : 4;
    u_char ip_v : 4;
#endif
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct ip6_hdr {
    union {
        struct {
            u_int32_t ip6_un1_flow;
            u_int16_t ip6_un1_plen;
            u_int8_t ip6_un1_nxt;
            u_int8_t ip6_un1_hlim;
        } ip6_un1;
        u_int8_t ip6_un2_vfc;
    } ip6_ctlun;
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
};

#define ip6_vfc ip6_ctlun.ip6_un2_vfc
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim

struct tcphdr {
    u_short th_sport;
    u_short th_dport;
    u_int32_t th_seq;
    u_int32_t th_ack;
    u_char th_x2 : 4;
    u_char th_off : 4;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

struct udphdr {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_ulen;
    u_short uh_sum;
};

#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#ifndef IPPROTO_L2TP
#define IPPROTO_L2TP 115
#endif

#ifndef TH_ECE
#define TH_ECE 0x40
#endif

#ifndef TH_CWR
#define TH_CWR 0x80
#endif

namespace packetdecode {

bool decodeIPv4(const u_char* ip_packet, int remaining_len, BasicPacketInfo* pkt_info) {
    if (remaining_len < static_cast<int>(sizeof(struct ip))) {
        return false;
    }

    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_packet);

    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);

    if (pkt_info != nullptr) {
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        pkt_info->src_ip = src_ip;
        pkt_info->dst_ip = dst_ip;
        pkt_info->addr_len = 4;
        pkt_info->ip_ttl = ip_header->ip_ttl;
        std::memcpy(pkt_info->src_bytes, &(ip_header->ip_src), 4);
        std::memcpy(pkt_info->dst_bytes, &(ip_header->ip_dst), 4);

        const int ip_header_len = ip_header->ip_hl * 4;
        const u_char* transport = ip_packet + ip_header_len;
        const int transport_len = remaining_len - ip_header_len;

        if (ip_header->ip_p == IPPROTO_TCP && transport_len >= 20) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
            pkt_info->src_port = ntohs(tcp->th_sport);
            pkt_info->dst_port = ntohs(tcp->th_dport);
            pkt_info->protocol = 6;
            pkt_info->has_fin = (tcp->th_flags & TH_FIN) != 0;
            pkt_info->has_psh = (tcp->th_flags & TH_PUSH) != 0;
            pkt_info->has_urg = (tcp->th_flags & TH_URG) != 0;
            pkt_info->has_ece = (tcp->th_flags & TH_ECE) != 0;
            pkt_info->has_syn = (tcp->th_flags & TH_SYN) != 0;
            pkt_info->has_ack = (tcp->th_flags & TH_ACK) != 0;
            pkt_info->has_cwr = (tcp->th_flags & TH_CWR) != 0;
            pkt_info->has_rst = (tcp->th_flags & TH_RST) != 0;
            pkt_info->tcp_window = ntohs(tcp->th_win);
            pkt_info->header_bytes = static_cast<uint32_t>(tcp->th_off * 4);
            const int payload = ntohs(ip_header->ip_len) - ip_header_len - static_cast<int>(tcp->th_off * 4);
            pkt_info->payload_bytes = payload > 0 ? static_cast<uint32_t>(payload) : 0;
        } else if (ip_header->ip_p == IPPROTO_UDP && transport_len >= 8) {
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
            pkt_info->src_port = ntohs(udp->uh_sport);
            pkt_info->dst_port = ntohs(udp->uh_dport);
            pkt_info->protocol = 17;
            pkt_info->has_fin = false;
            pkt_info->has_psh = false;
            pkt_info->has_urg = false;
            pkt_info->has_ece = false;
            pkt_info->has_syn = false;
            pkt_info->has_ack = false;
            pkt_info->has_cwr = false;
            pkt_info->has_rst = false;
            pkt_info->tcp_window = 0;
            pkt_info->header_bytes = 8;
            pkt_info->payload_bytes = ntohs(udp->uh_ulen) > 8 ? ntohs(udp->uh_ulen) - 8 : 0;
        }
    }

    return true;
}

bool decodeIPv6(const u_char* ip_packet, int remaining_len, BasicPacketInfo* pkt_info) {
    if (remaining_len < static_cast<int>(sizeof(struct ip6_hdr))) {
        return false;
    }

    const struct ip6_hdr* ip6_header = reinterpret_cast<const struct ip6_hdr*>(ip_packet);

    char src_ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);

    if (pkt_info != nullptr) {
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        pkt_info->src_ip = src_ip;
        pkt_info->dst_ip = dst_ip;
        pkt_info->addr_len = 16;
        pkt_info->ip_ttl = ip6_header->ip6_hlim;
        std::memcpy(pkt_info->src_bytes, &(ip6_header->ip6_src), 16);
        std::memcpy(pkt_info->dst_bytes, &(ip6_header->ip6_dst), 16);

        const u_char* transport = ip_packet + sizeof(struct ip6_hdr);
        const int transport_len = remaining_len - static_cast<int>(sizeof(struct ip6_hdr));

        if (ip6_header->ip6_nxt == IPPROTO_TCP && transport_len >= 20) {
            const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(transport);
            pkt_info->src_port = ntohs(tcp->th_sport);
            pkt_info->dst_port = ntohs(tcp->th_dport);
            pkt_info->protocol = 6;
            pkt_info->has_fin = (tcp->th_flags & TH_FIN) != 0;
            pkt_info->has_psh = (tcp->th_flags & TH_PUSH) != 0;
            pkt_info->has_urg = (tcp->th_flags & TH_URG) != 0;
            pkt_info->has_ece = (tcp->th_flags & TH_ECE) != 0;
            pkt_info->has_syn = (tcp->th_flags & TH_SYN) != 0;
            pkt_info->has_ack = (tcp->th_flags & TH_ACK) != 0;
            pkt_info->has_cwr = (tcp->th_flags & TH_CWR) != 0;
            pkt_info->has_rst = (tcp->th_flags & TH_RST) != 0;
            pkt_info->tcp_window = ntohs(tcp->th_win);
            pkt_info->header_bytes = static_cast<uint32_t>(tcp->th_off * 4);
            const int payload = ntohs(ip6_header->ip6_plen) - static_cast<int>(tcp->th_off * 4);
            pkt_info->payload_bytes = payload > 0 ? static_cast<uint32_t>(payload) : 0;
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP && transport_len >= 8) {
            const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(transport);
            pkt_info->src_port = ntohs(udp->uh_sport);
            pkt_info->dst_port = ntohs(udp->uh_dport);
            pkt_info->protocol = 17;
            pkt_info->has_fin = false;
            pkt_info->has_psh = false;
            pkt_info->has_urg = false;
            pkt_info->has_ece = false;
            pkt_info->has_syn = false;
            pkt_info->has_ack = false;
            pkt_info->has_cwr = false;
            pkt_info->has_rst = false;
            pkt_info->tcp_window = 0;
            pkt_info->header_bytes = 8;
            pkt_info->payload_bytes = ntohs(udp->uh_ulen) > 8 ? ntohs(udp->uh_ulen) - 8 : 0;
        }
    }

    return true;
}

bool decodeL2TP(const u_char* ip_packet, int remaining_len, BasicPacketInfo* pkt_info) {
    if (remaining_len < static_cast<int>(sizeof(struct ip))) {
        return false;
    }

    const struct ip* ip_header = reinterpret_cast<const struct ip*>(ip_packet);
    if (ip_header->ip_p != IPPROTO_L2TP) {
        return false;
    }

    const int ip_header_len = ip_header->ip_hl * 4;
    const u_char* l2tp_payload = ip_packet + ip_header_len;
    const int l2tp_remaining = remaining_len - ip_header_len;

    if (l2tp_remaining < 6) {
        return false;
    }

    const u_char* inner_packet = l2tp_payload + 6;
    const int inner_remaining = l2tp_remaining - 6;

    if (inner_remaining >= static_cast<int>(sizeof(struct ip))) {
        const struct ip* inner_ip = reinterpret_cast<const struct ip*>(inner_packet);
        if (inner_ip->ip_v == 4) {
            return decodeIPv4(inner_packet, inner_remaining, pkt_info);
        }
        if (inner_ip->ip_v == 6) {
            return decodeIPv6(inner_packet, inner_remaining, pkt_info);
        }
    }

    return false;
}

// NOTE: This function currently creates fake IP addresses from EtherType bytes (Java compatibility quirk).
// TODO: Reimplement with proper ARP structure parsing for future security analysis features.
/*
bool decodeArpCompat(u_short eth_type,
                     const u_char* payload,
                     int remaining_len,
                     BasicPacketInfo* pkt_info) {
#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif
    if (eth_type != ETHERTYPE_ARP || remaining_len < 6 || pkt_info == nullptr) {
        return false;
    }

    // Match observed Java artifact for ARP-like records:
    // src: [eth_type_hi].[eth_type_lo].[payload0].[payload1] => 8.6.0.1
    // dst: [payload2].[payload3].[payload4].[payload5]       => 8.0.6.4
    const uint8_t src0 = static_cast<uint8_t>((eth_type >> 8) & 0xFF);
    const uint8_t src1 = static_cast<uint8_t>(eth_type & 0xFF);

    pkt_info->src_bytes[0] = src0;
    pkt_info->src_bytes[1] = src1;
    pkt_info->src_bytes[2] = payload[0];
    pkt_info->src_bytes[3] = payload[1];

    pkt_info->dst_bytes[0] = payload[2];
    pkt_info->dst_bytes[1] = payload[3];
    pkt_info->dst_bytes[2] = payload[4];
    pkt_info->dst_bytes[3] = payload[5];

    pkt_info->src_ip = std::to_string(pkt_info->src_bytes[0]) + "." +
                       std::to_string(pkt_info->src_bytes[1]) + "." +
                       std::to_string(pkt_info->src_bytes[2]) + "." +
                       std::to_string(pkt_info->src_bytes[3]);
    pkt_info->dst_ip = std::to_string(pkt_info->dst_bytes[0]) + "." +
                       std::to_string(pkt_info->dst_bytes[1]) + "." +
                       std::to_string(pkt_info->dst_bytes[2]) + "." +
                       std::to_string(pkt_info->dst_bytes[3]);

    pkt_info->addr_len = 4;
    pkt_info->src_port = 0;
    pkt_info->dst_port = 0;
    pkt_info->protocol = 0;
    pkt_info->payload_bytes = 0;
    pkt_info->header_bytes = 0;
    pkt_info->has_fin = false;
    pkt_info->has_psh = false;
    pkt_info->has_urg = false;
    pkt_info->has_ece = false;
    pkt_info->has_syn = false;
    pkt_info->has_ack = false;
    pkt_info->has_cwr = false;
    pkt_info->has_rst = false;
    pkt_info->tcp_window = 0;
    return true;
}
*/

}  // namespace packetdecode
