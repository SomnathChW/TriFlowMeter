// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (C) 2026 | Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "BasicFlow.h"

#include <algorithm>
#include <ctime>

namespace {

uint64_t toMicros(uint32_t sec, uint32_t usec) {
    return static_cast<uint64_t>(sec) * 1000000ULL + static_cast<uint64_t>(usec);
}

}  // namespace

BasicFlow::BasicFlow(const BasicPacketInfo& pkt, uint64_t activity_timeout_micros_value) {
    activity_timeout_micros = activity_timeout_micros_value;
    flow_id = pkt.fwdFlowId();
    src_ip = pkt.src_ip;
    dst_ip = pkt.dst_ip;
    src_port = pkt.src_port;
    dst_port = pkt.dst_port;
    protocol = pkt.protocol;
    start_time_sec = pkt.timestamp_sec;
    start_time_usec = pkt.timestamp_usec;
    last_seen_sec = pkt.timestamp_sec;
    last_seen_usec = pkt.timestamp_usec;
    flow_start_time = packetTimeMicros(pkt);
    flow_last_seen = flow_start_time;
    start_active_time = flow_start_time;
    end_active_time = flow_start_time;

    updateFlowBulk(pkt);
    detectUpdateSubflows(pkt);
    checkFlags(pkt);

    flow_length_stats.add(static_cast<double>(pkt.payload_bytes));
    if (src_ip == pkt.src_ip) {
        min_seg_size_forward = pkt.header_bytes;
        init_win_bytes_forward = pkt.tcp_window;
        flow_length_stats.add(static_cast<double>(pkt.payload_bytes));
        fwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        f_header_bytes = pkt.header_bytes;
        forward_last_seen = flow_start_time;
        forward_bytes += pkt.payload_bytes;
        forward_packets++;
        if (pkt.has_psh) {
            f_psh_cnt++;
        }
        if (pkt.has_urg) {
            f_urg_cnt++;
        }
    } else {
        init_win_bytes_backward = pkt.tcp_window;
        flow_length_stats.add(static_cast<double>(pkt.payload_bytes));
        bwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        b_header_bytes = pkt.header_bytes;
        backward_last_seen = flow_start_time;
        backward_bytes += pkt.payload_bytes;
        backward_packets++;
        if (pkt.has_psh) {
            b_psh_cnt++;
        }
        if (pkt.has_urg) {
            b_urg_cnt++;
        }
    }

    if (pkt.has_rst) {
        finished = true;
    } else if (pkt.has_fin) {
        fwd_fin_flags = 1;
    }
}

BasicFlow::BasicFlow(const BasicPacketInfo& pkt,
                     const std::string& old_src_ip,
                     const std::string& old_dst_ip,
                     uint16_t old_src_port,
                     uint16_t old_dst_port,
                     uint64_t activity_timeout_micros_value) {
    activity_timeout_micros = activity_timeout_micros_value;
    flow_id = pkt.fwdFlowId();
    src_ip = old_src_ip;
    dst_ip = old_dst_ip;
    src_port = old_src_port;
    dst_port = old_dst_port;
    protocol = pkt.protocol;
    start_time_sec = pkt.timestamp_sec;
    start_time_usec = pkt.timestamp_usec;
    last_seen_sec = pkt.timestamp_sec;
    last_seen_usec = pkt.timestamp_usec;
    flow_start_time = packetTimeMicros(pkt);
    flow_last_seen = flow_start_time;
    start_active_time = flow_start_time;
    end_active_time = flow_start_time;

    updateFlowBulk(pkt);
    detectUpdateSubflows(pkt);
    checkFlags(pkt);
    flow_length_stats.add(static_cast<double>(pkt.payload_bytes));

    if (src_ip == pkt.src_ip) {
        min_seg_size_forward = pkt.header_bytes;
        init_win_bytes_forward = pkt.tcp_window;
        flow_length_stats.add(static_cast<double>(pkt.payload_bytes));
        fwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        f_header_bytes = pkt.header_bytes;
        forward_last_seen = flow_start_time;
        forward_packets++;
        forward_bytes = pkt.payload_bytes;
        backward_bytes = 0;
        if (pkt.has_psh) {
            f_psh_cnt++;
        }
        if (pkt.has_urg) {
            f_urg_cnt++;
        }
    } else {
        init_win_bytes_backward = pkt.tcp_window;
        flow_length_stats.add(static_cast<double>(pkt.payload_bytes));
        bwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        b_header_bytes = pkt.header_bytes;
        backward_last_seen = flow_start_time;
        backward_packets++;
        forward_bytes = 0;
        backward_bytes = pkt.payload_bytes;
        if (pkt.has_psh) {
            b_psh_cnt++;
        }
        if (pkt.has_urg) {
            b_urg_cnt++;
        }
    }

    if (pkt.has_rst) {
        finished = true;
    } else if (pkt.has_fin) {
        if (old_src_ip == pkt.src_ip) {
            fwd_fin_flags = 1;
        } else {
            bwd_fin_flags = 1;
        }
    }
}

void BasicFlow::addPacket(const BasicPacketInfo& pkt) {
    updateFlowBulk(pkt);
    detectUpdateSubflows(pkt);
    checkFlags(pkt);

    const uint64_t current_timestamp = packetTimeMicros(pkt);
    const uint64_t previous_flow_last_seen = flow_last_seen;
    updateActiveIdleTime(current_timestamp, activity_timeout_micros);

    const bool is_forward = (src_ip == pkt.src_ip);
    flow_length_stats.add(static_cast<double>(pkt.payload_bytes));

    if (is_forward) {
        if (pkt.payload_bytes >= 1) {
            act_data_pkt_forward++;
        }
        fwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        f_header_bytes += pkt.header_bytes;
        if (forward_packets > 0) {
            forward_iat.add(static_cast<double>(current_timestamp - forward_last_seen));
        }
        forward_packets++;
        forward_last_seen = current_timestamp;
        forward_bytes += pkt.payload_bytes;
        min_seg_size_forward = std::min<uint64_t>(pkt.header_bytes, min_seg_size_forward);
    } else {
        bwd_pkt_stats.add(static_cast<double>(pkt.payload_bytes));
        init_win_bytes_backward = pkt.tcp_window;
        b_header_bytes += pkt.header_bytes;
        if (backward_packets > 0) {
            backward_iat.add(static_cast<double>(current_timestamp - backward_last_seen));
        }
        backward_packets++;
        backward_last_seen = current_timestamp;
        backward_bytes += pkt.payload_bytes;
    }

    flow_iat.add(static_cast<double>(current_timestamp - previous_flow_last_seen));

    last_seen_sec = pkt.timestamp_sec;
    last_seen_usec = pkt.timestamp_usec;
    flow_last_seen = current_timestamp;

    if (pkt.has_rst) {
        finished = true;
        return;
    }

    if (pkt.has_fin) {
        if (is_forward) {
            fwd_fin_flags = 1;
        } else {
            bwd_fin_flags = 1;
        }

        // Keep Java-compatible FIN close behavior.
        if ((bwd_fin_flags + bwd_fin_flags) == 2) {
            finished = true;
        }
    }
}

int BasicFlow::packetCount() const {
    return forward_packets + backward_packets;
}

uint64_t BasicFlow::packetTimeMicros(const BasicPacketInfo& pkt) const {
    return toMicros(pkt.timestamp_sec, pkt.timestamp_usec);
}

void BasicFlow::checkFlags(const BasicPacketInfo& pkt) {
    if (pkt.has_fin) {
        fin_flag_count++;
    }
    if (pkt.has_syn) {
        syn_flag_count++;
    }
    if (pkt.has_rst) {
        rst_flag_count++;
    }
    if (pkt.has_psh) {
        psh_flag_count++;
    }
    if (pkt.has_ack) {
        ack_flag_count++;
    }
    if (pkt.has_urg) {
        urg_flag_count++;
    }
    if (pkt.has_cwr) {
        cwr_flag_count++;
    }
    if (pkt.has_ece) {
        ece_flag_count++;
    }
}

void BasicFlow::detectUpdateSubflows(const BasicPacketInfo& pkt) {
    const uint64_t ts = packetTimeMicros(pkt);
    if (sf_last_packet_ts == static_cast<uint64_t>(-1)) {
        sf_last_packet_ts = ts;
        sf_ac_helper = ts;
    }
    if (((ts - sf_last_packet_ts) / 1000000.0) > 1.0) {
        sf_count++;
        updateActiveIdleTime(ts, activity_timeout_micros);
        sf_ac_helper = ts;
    }
    sf_last_packet_ts = ts;
}

void BasicFlow::updateFlowBulk(const BasicPacketInfo& pkt) {
    // Keep Java behavior (object identity check on byte arrays) by always taking backward path.
    updateBackwardBulk(pkt, flast_bulk_ts);
}

void BasicFlow::updateForwardBulk(const BasicPacketInfo& pkt, uint64_t ts_of_last_bulk_in_other) {
    const uint64_t size = pkt.payload_bytes;
    if (ts_of_last_bulk_in_other > fbulk_start_helper) {
        fbulk_start_helper = 0;
    }
    if (size == 0) {
        return;
    }

    const uint64_t ts = packetTimeMicros(pkt);
    if (fbulk_start_helper == 0) {
        fbulk_start_helper = ts;
        fbulk_packet_count_helper = 1;
        fbulk_size_helper = size;
        flast_bulk_ts = ts;
    } else {
        if (((ts - flast_bulk_ts) / 1000000.0) > 1.0) {
            fbulk_start_helper = ts;
            flast_bulk_ts = ts;
            fbulk_packet_count_helper = 1;
            fbulk_size_helper = size;
        } else {
            fbulk_packet_count_helper += 1;
            fbulk_size_helper += size;
            if (fbulk_packet_count_helper == 4) {
                fbulk_state_count += 1;
                fbulk_packet_count += fbulk_packet_count_helper;
                fbulk_size_total += fbulk_size_helper;
                fbulk_duration += ts - fbulk_start_helper;
            } else if (fbulk_packet_count_helper > 4) {
                fbulk_packet_count += 1;
                fbulk_size_total += size;
                fbulk_duration += ts - flast_bulk_ts;
            }
            flast_bulk_ts = ts;
        }
    }
}

void BasicFlow::updateBackwardBulk(const BasicPacketInfo& pkt, uint64_t ts_of_last_bulk_in_other) {
    const uint64_t size = pkt.payload_bytes;
    if (ts_of_last_bulk_in_other > bbulk_start_helper) {
        bbulk_start_helper = 0;
    }
    if (size == 0) {
        return;
    }

    const uint64_t ts = packetTimeMicros(pkt);
    if (bbulk_start_helper == 0) {
        bbulk_start_helper = ts;
        bbulk_packet_count_helper = 1;
        bbulk_size_helper = size;
        blast_bulk_ts = ts;
    } else {
        if (((ts - blast_bulk_ts) / 1000000.0) > 1.0) {
            bbulk_start_helper = ts;
            blast_bulk_ts = ts;
            bbulk_packet_count_helper = 1;
            bbulk_size_helper = size;
        } else {
            bbulk_packet_count_helper += 1;
            bbulk_size_helper += size;
            if (bbulk_packet_count_helper == 4) {
                bbulk_state_count += 1;
                bbulk_packet_count += bbulk_packet_count_helper;
                bbulk_size_total += bbulk_size_helper;
                bbulk_duration += ts - bbulk_start_helper;
            } else if (bbulk_packet_count_helper > 4) {
                bbulk_packet_count += 1;
                bbulk_size_total += size;
                bbulk_duration += ts - blast_bulk_ts;
            }
            blast_bulk_ts = ts;
        }
    }
}

void BasicFlow::updateActiveIdleTime(uint64_t current_time, uint64_t threshold) {
    if ((current_time - end_active_time) > threshold) {
        if ((end_active_time - start_active_time) > 0) {
            flow_active.add(static_cast<double>(end_active_time - start_active_time));
        }
        flow_idle.add(static_cast<double>(current_time - end_active_time));
        start_active_time = current_time;
        end_active_time = current_time;
    } else {
        end_active_time = current_time;
    }
}

uint64_t BasicFlow::getDuration() const {
    return flow_last_seen - flow_start_time;
}

uint64_t BasicFlow::getTotalBytes() const {
    return forward_bytes + backward_bytes;
}

double BasicFlow::getFlowBytesPerSecond() const {
    const double duration_sec = static_cast<double>(getDuration()) / 1000000.0;
    return static_cast<double>(getTotalBytes()) / duration_sec;
}

double BasicFlow::getFlowPacketsPerSecond() const {
    const double duration_sec = static_cast<double>(getDuration()) / 1000000.0;
    return static_cast<double>(packetCount()) / duration_sec;
}

double BasicFlow::getAveragePacketSize() const {
    return packetCount() > 0 ? flow_length_stats.sum / static_cast<double>(packetCount()) : 0.0;
}

double BasicFlow::getDownUpRatio() const {
    if (forward_packets > 0) {
        return static_cast<double>(backward_packets / forward_packets);
    }
    return 0.0;
}

double BasicFlow::getFwdPacketsPerSecond() const {
    const double duration_sec = static_cast<double>(getDuration()) / 1000000.0;
    if (duration_sec > 0.0) {
        return static_cast<double>(forward_packets) / duration_sec;
    }
    return 0.0;
}

double BasicFlow::getBwdPacketsPerSecond() const {
    const double duration_sec = static_cast<double>(getDuration()) / 1000000.0;
    if (duration_sec > 0.0) {
        return static_cast<double>(backward_packets) / duration_sec;
    }
    return 0.0;
}

double BasicFlow::getFwdIATTotal() const {
    return forward_packets > 1 ? forward_iat.sum : 0.0;
}

double BasicFlow::getFwdIATMean() const {
    return forward_packets > 1 ? forward_iat.mean : 0.0;
}

double BasicFlow::getFwdIATStd() const {
    return forward_packets > 1 ? forward_iat.stddev() : 0.0;
}

double BasicFlow::getFwdIATMax() const {
    return forward_packets > 1 ? forward_iat.max : 0.0;
}

double BasicFlow::getFwdIATMin() const {
    return forward_packets > 1 ? forward_iat.min : 0.0;
}

double BasicFlow::getBwdIATTotal() const {
    return backward_packets > 1 ? backward_iat.sum : 0.0;
}

double BasicFlow::getBwdIATMean() const {
    return backward_packets > 1 ? backward_iat.mean : 0.0;
}

double BasicFlow::getBwdIATStd() const {
    return backward_packets > 1 ? backward_iat.stddev() : 0.0;
}

double BasicFlow::getBwdIATMax() const {
    return backward_packets > 1 ? backward_iat.max : 0.0;
}

double BasicFlow::getBwdIATMin() const {
    return backward_packets > 1 ? backward_iat.min : 0.0;
}

uint64_t BasicFlow::getSubflowFwdPackets() const {
    if (sf_count <= 0) {
        return 0;
    }
    return static_cast<uint64_t>(forward_packets / sf_count);
}

uint64_t BasicFlow::getSubflowFwdBytes() const {
    if (sf_count <= 0) {
        return 0;
    }
    return forward_bytes / static_cast<uint64_t>(sf_count);
}

uint64_t BasicFlow::getSubflowBwdPackets() const {
    if (sf_count <= 0) {
        return 0;
    }
    return static_cast<uint64_t>(backward_packets / sf_count);
}

uint64_t BasicFlow::getSubflowBwdBytes() const {
    if (sf_count <= 0) {
        return 0;
    }
    return backward_bytes / static_cast<uint64_t>(sf_count);
}

uint64_t BasicFlow::getFwdBytesPerBulkAvg() const {
    if (fbulk_state_count != 0) {
        return fbulk_size_total / fbulk_state_count;
    }
    return 0;
}

uint64_t BasicFlow::getFwdPacketsPerBulkAvg() const {
    if (fbulk_state_count != 0) {
        return fbulk_packet_count / fbulk_state_count;
    }
    return 0;
}

uint64_t BasicFlow::getFwdBulkRateAvg() const {
    if (fbulk_duration != 0) {
        return static_cast<uint64_t>(fbulk_size_total / (static_cast<double>(fbulk_duration) / 1000000.0));
    }
    return 0;
}

uint64_t BasicFlow::getBwdBytesPerBulkAvg() const {
    if (bbulk_state_count != 0) {
        return bbulk_size_total / bbulk_state_count;
    }
    return 0;
}

uint64_t BasicFlow::getBwdPacketsPerBulkAvg() const {
    if (bbulk_state_count != 0) {
        return bbulk_packet_count / bbulk_state_count;
    }
    return 0;
}

uint64_t BasicFlow::getBwdBulkRateAvg() const {
    if (bbulk_duration != 0) {
        return static_cast<uint64_t>(bbulk_size_total / (static_cast<double>(bbulk_duration) / 1000000.0));
    }
    return 0;
}

std::string BasicFlow::getTimestampString() const {
    std::time_t raw = static_cast<std::time_t>(start_time_sec);
    std::tm* tm_info = std::localtime(&raw);
    if (tm_info == nullptr) {
        return "";
    }

    char buffer[64];
    if (std::strftime(buffer, sizeof(buffer), "%d/%m/%Y %I:%M:%S %p", tm_info) == 0) {
        return "";
    }
    return std::string(buffer);
}
