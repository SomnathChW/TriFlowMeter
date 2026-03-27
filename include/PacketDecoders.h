#pragma once

/*
 * TriFlowMeter - High-Performance Network Flow Analyzer
 * Copyright (C) 2026 Somnath Chowdhury
 * Author: Somnath Chowdhury (http://github.com/SomnathChW)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
