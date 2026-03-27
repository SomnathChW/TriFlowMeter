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

#include <chrono>
#include <cstdint>
#include <string>

#include "BasicPacketInfo.h"

class LiveDashboard {
public:
    LiveDashboard(const std::string& source_name, const std::string& output_path);

    void setPacketStats(const PacketStats& stats);
    void setWrittenFlows(std::uint64_t flows);
    void setActiveFlows(std::uint64_t flows);

    void refreshIfDue();
    void forceRefresh();
    void finalize();

private:
    std::string source_name_;
    std::string output_path_;
    PacketStats stats_{};
    std::uint64_t written_flows_ = 0;
    std::uint64_t active_flows_ = 0;

    bool initialized_ = false;
    std::chrono::steady_clock::time_point start_time_;
    std::chrono::steady_clock::time_point last_refresh_time_;

    static std::string shortCount(long long value);
    static std::string clip(const std::string& s, std::size_t width);
    void render();
};
