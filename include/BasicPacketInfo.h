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

#include <cstdint>
#include <string>

struct PacketStats {
    long long total = 0;
    long long valid = 0;
    long long discarded = 0;
    long long vpn_packets = 0;
};

struct BasicPacketInfo {
    std::string src_ip;
    std::string dst_ip;
    uint8_t src_bytes[16] = {0};
    uint8_t dst_bytes[16] = {0};
    int addr_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint32_t timestamp_sec = 0;
    uint32_t timestamp_usec = 0;
    uint32_t payload_bytes = 0;
    uint32_t header_bytes = 0;
    bool has_fin = false;
    bool has_psh = false;
    bool has_urg = false;
    bool has_ece = false;
    bool has_syn = false;
    bool has_ack = false;
    bool has_cwr = false;
    bool has_rst = false;
    int tcp_window = 0;
    uint8_t ip_ttl = 0;

    bool compareIPs() const {
        for (int i = 0; i < addr_len; i++) {
            if (src_bytes[i] != dst_bytes[i]) {
                const int src_signed = static_cast<int>(static_cast<int8_t>(src_bytes[i]));
                const int dst_signed = static_cast<int>(static_cast<int8_t>(dst_bytes[i]));
                return src_signed < dst_signed;
            }
        }
        return true;
    }

    std::string generateFlowId() const {
        bool forward = compareIPs();

        if (forward) {
            return src_ip + "-" + dst_ip + "-" + std::to_string(src_port) + "-" +
                   std::to_string(dst_port) + "-" + std::to_string(protocol);
        }

        return dst_ip + "-" + src_ip + "-" + std::to_string(dst_port) + "-" +
               std::to_string(src_port) + "-" + std::to_string(protocol);
    }

    std::string fwdFlowId() const {
        return src_ip + "-" + dst_ip + "-" + std::to_string(src_port) + "-" +
               std::to_string(dst_port) + "-" + std::to_string(protocol);
    }

    std::string bwdFlowId() const {
        return dst_ip + "-" + src_ip + "-" + std::to_string(dst_port) + "-" +
               std::to_string(src_port) + "-" + std::to_string(protocol);
    }
};
