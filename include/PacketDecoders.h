#pragma once

#include <pcap.h>

#include "BasicPacketInfo.h"

namespace packetdecode {

bool decodeIPv4(const u_char* ip_packet, int remaining_len, BasicPacketInfo* pkt_info = nullptr);
bool decodeIPv6(const u_char* ip_packet, int remaining_len, BasicPacketInfo* pkt_info = nullptr);
bool decodeL2TP(const u_char* ip_packet, int remaining_len);
bool decodeArpCompat(u_short eth_type,
                     const u_char* payload,
                     int remaining_len,
                     BasicPacketInfo* pkt_info = nullptr);

}  // namespace packetdecode
