#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#include "BasicPacketInfo.h"

class STDWriter {
public:
    STDWriter(const std::string& title, const std::string& source_name, const std::string& output_path);

    void setPacketStats(const PacketStats& stats);
    void setWrittenFlows(std::uint64_t flows);
    void setActiveFlows(std::uint64_t flows);

    void refreshIfDue();
    void forceRefresh();
    void finalize();

private:
    std::string title_;
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
    static std::string makeRow(const std::string& content, std::size_t inner_width);
    void render();
};
