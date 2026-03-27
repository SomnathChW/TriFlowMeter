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

#include <cmath>

#include "BasicPacketInfo.h"

struct RunningStats {
    uint64_t n = 0;
    double mean = 0.0;
    double m2 = 0.0;
    double sum = 0.0;
    double min = 0.0;
    double max = 0.0;

    void add(double v) {
        if (n == 0) {
            mean = 0.0;
            m2 = 0.0;
            min = v;
            max = v;
        }

        n++;
        const double dev = v - mean;
        const double n_dev = dev / static_cast<double>(n);
        mean += n_dev;
        m2 += (static_cast<double>(n) - 1.0) * dev * n_dev;

        sum += v;
        if (v < min) {
            min = v;
        }
        if (v > max) {
            max = v;
        }
    }

    double stddev() const {
        if (n <= 1) {
            return 0.0;
        }
        const double var = variance();
        return var > 0.0 ? std::sqrt(var) : 0.0;
    }

    double variance() const {
        if (n <= 1) {
            return 0.0;
        }
        return m2 / static_cast<double>(n - 1);
    }
};

class BasicFlow {
public:
    static constexpr uint64_t kDefaultActivityTimeoutMicros = 5000000ULL;

    std::string flow_id;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;
    uint32_t start_time_sec = 0;
    uint32_t start_time_usec = 0;
    uint32_t last_seen_sec = 0;
    uint32_t last_seen_usec = 0;
    uint64_t flow_start_time = 0;
    uint64_t flow_last_seen = 0;
    uint64_t start_active_time = 0;
    uint64_t end_active_time = 0;
    uint64_t forward_last_seen = 0;
    uint64_t backward_last_seen = 0;
    int forward_packets = 0;
    int backward_packets = 0;
    uint64_t forward_bytes = 0;
    uint64_t backward_bytes = 0;
    uint64_t f_header_bytes = 0;
    uint64_t b_header_bytes = 0;
    int init_win_bytes_forward = 0;
    int init_win_bytes_backward = 0;
    uint64_t act_data_pkt_forward = 0;
    uint64_t min_seg_size_forward = 0;
    int f_psh_cnt = 0;
    int b_psh_cnt = 0;
    int f_urg_cnt = 0;
    int b_urg_cnt = 0;
    int fin_flag_count = 0;
    int syn_flag_count = 0;
    int rst_flag_count = 0;
    int psh_flag_count = 0;
    int ack_flag_count = 0;
    int urg_flag_count = 0;
    int cwr_flag_count = 0;
    int ece_flag_count = 0;

    RunningStats fwd_pkt_stats;
    RunningStats bwd_pkt_stats;
    RunningStats flow_iat;
    RunningStats forward_iat;
    RunningStats backward_iat;
    RunningStats flow_length_stats;
    RunningStats flow_active;
    RunningStats flow_idle;

    uint64_t sf_last_packet_ts = static_cast<uint64_t>(-1);
    int sf_count = 1;
    uint64_t sf_ac_helper = static_cast<uint64_t>(-1);

    uint64_t fbulk_duration = 0;
    uint64_t fbulk_packet_count = 0;
    uint64_t fbulk_size_total = 0;
    uint64_t fbulk_state_count = 0;
    uint64_t fbulk_packet_count_helper = 0;
    uint64_t fbulk_start_helper = 0;
    uint64_t fbulk_size_helper = 0;
    uint64_t flast_bulk_ts = 0;

    uint64_t bbulk_duration = 0;
    uint64_t bbulk_packet_count = 0;
    uint64_t bbulk_size_total = 0;
    uint64_t bbulk_state_count = 0;
    uint64_t bbulk_packet_count_helper = 0;
    uint64_t bbulk_start_helper = 0;
    uint64_t bbulk_size_helper = 0;
    uint64_t blast_bulk_ts = 0;

    int fwd_fin_flags = 0;
    int bwd_fin_flags = 0;
    bool finished = false;
    uint64_t activity_timeout_micros = kDefaultActivityTimeoutMicros;

    BasicFlow() = default;
    explicit BasicFlow(const BasicPacketInfo& pkt,
                       uint64_t activity_timeout_micros = kDefaultActivityTimeoutMicros);
    BasicFlow(const BasicPacketInfo& pkt,
              const std::string& old_src_ip,
              const std::string& old_dst_ip,
              uint16_t old_src_port,
              uint16_t old_dst_port,
              uint64_t activity_timeout_micros = kDefaultActivityTimeoutMicros);

    void addPacket(const BasicPacketInfo& pkt);
    void updateActiveIdleTime(uint64_t current_time, uint64_t threshold);

    int packetCount() const;
    uint64_t getDuration() const;
    uint64_t getTotalBytes() const;
    double getFlowBytesPerSecond() const;
    double getFlowPacketsPerSecond() const;
    double getAveragePacketSize() const;
    double getDownUpRatio() const;
    double getFwdPacketsPerSecond() const;
    double getBwdPacketsPerSecond() const;
    double getFwdIATTotal() const;
    double getFwdIATMean() const;
    double getFwdIATStd() const;
    double getFwdIATMax() const;
    double getFwdIATMin() const;
    double getBwdIATTotal() const;
    double getBwdIATMean() const;
    double getBwdIATStd() const;
    double getBwdIATMax() const;
    double getBwdIATMin() const;
    uint64_t getSubflowFwdPackets() const;
    uint64_t getSubflowFwdBytes() const;
    uint64_t getSubflowBwdPackets() const;
    uint64_t getSubflowBwdBytes() const;
    uint64_t getFwdBytesPerBulkAvg() const;
    uint64_t getFwdPacketsPerBulkAvg() const;
    uint64_t getFwdBulkRateAvg() const;
    uint64_t getBwdBytesPerBulkAvg() const;
    uint64_t getBwdPacketsPerBulkAvg() const;
    uint64_t getBwdBulkRateAvg() const;
    std::string getTimestampString() const;

private:
    uint64_t packetTimeMicros(const BasicPacketInfo& pkt) const;
    void checkFlags(const BasicPacketInfo& pkt);
    void detectUpdateSubflows(const BasicPacketInfo& pkt);
    void updateFlowBulk(const BasicPacketInfo& pkt);
    void updateForwardBulk(const BasicPacketInfo& pkt, uint64_t ts_of_last_bulk_in_other);
    void updateBackwardBulk(const BasicPacketInfo& pkt, uint64_t ts_of_last_bulk_in_other);
};
