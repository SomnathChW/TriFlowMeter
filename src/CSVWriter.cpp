// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "CSVWriter.h"

#include "JavaNumberFormat.h"

using javafmt::formatJavaLikeDouble;

void CSVWriter::writeHeader(std::ostream& out) {
    out << "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,"
        << "Flow Start Time,Flow End Time,Flow Duration,"
        << "Total Fwd Packets,Total Bwd Packets,Total Fwd Bytes,Total Bwd Bytes,"
        << "Fwd Header Length,Bwd Header Length,Fwd Act Data Pkts,Bwd Act Data Pkts,"
        << "Flow Packets/s,Flow Bytes/s,Fwd Packets/s,Bwd Packets/s,"
        << "Payload Ratio,Packet Count Ratio,Header-to-Total Ratio,"
        << "Fwd Pkt Len Min,Fwd Pkt Len Max,Fwd Pkt Len Mean,Fwd Pkt Len Std,"
        << "Bwd Pkt Len Min,Bwd Pkt Len Max,Bwd Pkt Len Mean,Bwd Pkt Len Std,"
        << "Pkt Len Min,Pkt Len Max,Pkt Len Mean,Pkt Len Std,"
        << "Fwd IAT Total,Fwd IAT Min,Fwd IAT Max,Fwd IAT Mean,Fwd IAT Std,"
        << "Bwd IAT Total,Bwd IAT Min,Bwd IAT Max,Bwd IAT Mean,Bwd IAT Std,"
        << "Flow IAT Total,Flow IAT Min,Flow IAT Max,Flow IAT Mean,Flow IAT Std,"
        << "SYN Flag Count,ACK Flag Count,FIN Flag Count,RST Flag Count,"
        << "PSH Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
        << "SYN Flag Rate,ACK Flag Rate,FIN Flag Rate,RST Flag Rate,"
        << "PSH Flag Rate,URG Flag Rate,CWR Flag Rate,ECE Flag Rate,"
        << "Fwd Init Win Size,Bwd Init Win Size,Fwd Min Segment Size,"
        << "Fwd Initial TTL,Bwd Initial TTL,"
        << "Active Min,Active Max,Active Mean,Active Std,"
        << "Idle Min,Idle Max,Idle Mean,Idle Std,"
        << "Label\n";
}

bool CSVWriter::writeFlowRow(std::ostream& out, const BasicFlow& flow, const std::string& label) {
    if (flow.packetCount() <= 0) {
        return false;
    }

    const bool has_fwd_stats = flow.fwd_pkt_stats.n > 0;
    const bool has_bwd_stats = flow.bwd_pkt_stats.n > 0;
    const bool has_pkt_len = flow.flow_length_stats.n > 0;
    const bool has_fwd_iat = flow.forward_packets > 1;
    const bool has_bwd_iat = flow.backward_packets > 1;
    const bool has_flow_iat = flow.flow_iat.n > 0;
    const bool has_active = flow.flow_active.n > 0;
    const bool has_idle = flow.flow_idle.n > 0;

    const double duration_sec = static_cast<double>(flow.getDuration()) / 1000000.0;
    const uint64_t total_bytes = flow.forward_bytes + flow.backward_bytes;
    const uint64_t total_header_bytes = flow.f_header_bytes + flow.b_header_bytes;
    const int total_packets = flow.forward_packets + flow.backward_packets;

    // Calculate export-time ratios and rates
    const double flow_packets_per_sec = (duration_sec > 0.0) ? (total_packets / duration_sec) : 0.0;
    const double flow_bytes_per_sec = (duration_sec > 0.0) ? (total_bytes / duration_sec) : 0.0;
    const double fwd_packets_per_sec = (duration_sec > 0.0) ? (flow.forward_packets / duration_sec) : 0.0;
    const double bwd_packets_per_sec = (duration_sec > 0.0) ? (flow.backward_packets / duration_sec) : 0.0;
    const double payload_ratio = (flow.forward_bytes > 0) ? (static_cast<double>(flow.backward_bytes) / flow.forward_bytes) : 0.0;
    const double packet_count_ratio = (flow.forward_packets > 0) ? (static_cast<double>(flow.backward_packets) / flow.forward_packets) : 0.0;
    const uint64_t total_all_bytes = total_bytes + total_header_bytes;
    const double header_to_total_ratio = (total_all_bytes > 0) ? (static_cast<double>(total_header_bytes) / total_all_bytes) : 0.0;

    // Flow Metadata (9 features)
    out << flow.flow_id << ','
        << flow.src_ip << ','
        << flow.src_port << ','
        << flow.dst_ip << ','
        << flow.dst_port << ','
        << static_cast<int>(flow.protocol) << ','
        << flow.getTimestampString() << ','
        << flow.getFlowEndTimeString() << ','
        << flow.getDuration() << ',';

    // Base Volumetrics (8 features)
    out << flow.forward_packets << ','
        << flow.backward_packets << ','
        << flow.forward_bytes << ','
        << flow.backward_bytes << ','
        << flow.f_header_bytes << ','
        << flow.b_header_bytes << ','
        << flow.act_data_pkt_forward << ','
        << flow.act_data_pkt_backward << ',';

    // Rates & Ratios (7 features)
    out << formatJavaLikeDouble(flow_packets_per_sec) << ','
        << formatJavaLikeDouble(flow_bytes_per_sec) << ','
        << formatJavaLikeDouble(fwd_packets_per_sec) << ','
        << formatJavaLikeDouble(bwd_packets_per_sec) << ','
        << formatJavaLikeDouble(payload_ratio) << ','
        << formatJavaLikeDouble(packet_count_ratio) << ','
        << formatJavaLikeDouble(header_to_total_ratio) << ',';

    // Packet Size Profiles - Fwd (4 features)
    out << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.min) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.max) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.mean) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.stddev()) : std::string("0")) << ',';

    // Packet Size Profiles - Bwd (4 features)
    out << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.min) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.max) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.mean) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.stddev()) : std::string("0")) << ',';

    // Packet Size Profiles - Total (4 features)
    out << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.min) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.max) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.mean) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.stddev()) : std::string("0")) << ',';

    // IAT Profiles - Fwd (5 features)
    out << (has_fwd_iat ? formatJavaLikeDouble(flow.forward_iat.sum) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.forward_iat.min) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.forward_iat.max) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.forward_iat.mean) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.forward_iat.stddev()) : std::string("0")) << ',';

    // IAT Profiles - Bwd (5 features)
    out << (has_bwd_iat ? formatJavaLikeDouble(flow.backward_iat.sum) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.backward_iat.min) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.backward_iat.max) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.backward_iat.mean) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.backward_iat.stddev()) : std::string("0")) << ',';

    // IAT Profiles - Flow (5 features)
    out << (has_flow_iat ? formatJavaLikeDouble(flow.flow_iat.sum) : std::string("0")) << ','
        << (has_flow_iat ? formatJavaLikeDouble(flow.flow_iat.min) : std::string("0")) << ','
        << (has_flow_iat ? formatJavaLikeDouble(flow.flow_iat.max) : std::string("0")) << ','
        << (has_flow_iat ? formatJavaLikeDouble(flow.flow_iat.mean) : std::string("0")) << ','
        << (has_flow_iat ? formatJavaLikeDouble(flow.flow_iat.stddev()) : std::string("0")) << ',';

    // TCP/IP Mechanics - TCP Flag Counts (8 features)
    out << flow.syn_flag_count << ','
        << flow.ack_flag_count << ','
        << flow.fin_flag_count << ','
        << flow.rst_flag_count << ','
        << flow.psh_flag_count << ','
        << flow.urg_flag_count << ','
        << flow.cwr_flag_count << ','
        << flow.ece_flag_count << ',';

    // TCP/IP Mechanics - TCP Flag Rates (8 features)
    const double tp = static_cast<double>(total_packets);
    out << formatJavaLikeDouble(flow.syn_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.ack_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.fin_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.rst_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.psh_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.urg_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.cwr_flag_count / tp) << ','
        << formatJavaLikeDouble(flow.ece_flag_count / tp) << ',';

    // TCP/IP Mechanics - Window & Segment (3 features)
    out << flow.init_win_bytes_forward << ','
        << flow.init_win_bytes_backward << ','
        << flow.min_seg_size_forward << ',';

    // TCP/IP Mechanics - TTL (2 features)
    out << static_cast<int>(flow.fwd_initial_ttl) << ','
        << static_cast<int>(flow.bwd_initial_ttl) << ',';

    // Connection States - Active (4 features)
    out << (has_active ? formatJavaLikeDouble(flow.flow_active.min) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.max) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.mean) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.stddev()) : std::string("0")) << ',';

    // Connection States - Idle (4 features)
    out << (has_idle ? formatJavaLikeDouble(flow.flow_idle.min) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.max) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.mean) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.stddev()) : std::string("0")) << ',';

    // Label
    out << label << '\n';

    return true;
}
