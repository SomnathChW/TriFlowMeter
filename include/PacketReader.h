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

#include <csignal>
#include <cstdint>
#include <functional>
#include <string>

#include "BasicPacketInfo.h"
#include "FlowGenerator.h"

class PacketReader {
public:
    enum class Mode {
        Offline,
        Live,
    };

    explicit PacketReader(const std::string& pcap_path);
    PacketReader(Mode mode, const std::string& source, int snaplen, bool promiscuous, int timeout_ms);
    ~PacketReader();

    bool open();
    bool readAll(FlowGenerator& flow_gen,
                 PacketStats& stats,
                 bool read_ipv4 = true,
                 bool read_ipv6 = true,
                 const volatile std::sig_atomic_t* stop_flag = nullptr,
                 std::function<void(const PacketStats&)> packet_progress_cb = nullptr);

    const std::string& getLastError() const;

private:
    Mode mode_;
    std::string pcap_path_;
    std::string last_error_;
    pcap_t* handle_;
    int snaplen_;
    bool promiscuous_;
    int timeout_ms_;
};
