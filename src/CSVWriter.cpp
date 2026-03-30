// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "CSVWriter.h"

#include "JavaNumberFormat.h"

using javafmt::formatJavaLikeDouble;

void CSVWriter::writeHeader(std::ostream& out) {
    out << "Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp,Flow Duration,"
        << "Total Fwd Packet,Total Bwd packets,Total Length of Fwd Packet,Total Length of Bwd Packet,"
        << "Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,"
        << "Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,"
        << "Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,"
        << "Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,"
        << "Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,"
        << "Fwd PSH Flags,Bwd PSH Flags,Fwd URG Flags,Bwd URG Flags,Fwd Header Length,Bwd Header Length,"
        << "Fwd Packets/s,Bwd Packets/s,Packet Length Min,Packet Length Max,Packet Length Mean,Packet Length Std,Packet Length Variance,"
        << "FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWR Flag Count,ECE Flag Count,"
        << "Down/Up Ratio,Average Packet Size,Fwd Segment Size Avg,Bwd Segment Size Avg,"
        << "Fwd Bytes/Bulk Avg,Fwd Packet/Bulk Avg,Fwd Bulk Rate Avg,Bwd Bytes/Bulk Avg,Bwd Packet/Bulk Avg,Bwd Bulk Rate Avg,"
        << "Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,"
        << "FWD Init Win Bytes,Bwd Init Win Bytes,Fwd Act Data Pkts,Fwd Seg Size Min,"
        << "Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label\n";
}

bool CSVWriter::writeFlowRow(std::ostream& out, const BasicFlow& flow) {
    if (flow.packetCount() <= 0) {
        return false;
    }

    const bool has_fwd_stats = flow.fwd_pkt_stats.n > 0;
    const bool has_bwd_stats = flow.bwd_pkt_stats.n > 0;
    const bool has_fwd_iat = flow.forward_packets > 1;
    const bool has_bwd_iat = flow.backward_packets > 1;
    const bool has_pkt_len = flow.packetCount() > 0;
    const bool has_active = flow.flow_active.n > 0;
    const bool has_idle = flow.flow_idle.n > 0;

    out << flow.flow_id << ','
        << flow.src_ip << ','
        << flow.src_port << ','
        << flow.dst_ip << ','
        << flow.dst_port << ','
        << static_cast<int>(flow.protocol) << ','
        << flow.getTimestampString() << ','
        << flow.getDuration() << ','
        << flow.fwd_pkt_stats.n << ','
        << flow.bwd_pkt_stats.n << ','
        << formatJavaLikeDouble(flow.fwd_pkt_stats.sum) << ','
        << formatJavaLikeDouble(flow.bwd_pkt_stats.sum) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.max) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.min) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.mean) : std::string("0")) << ','
        << (has_fwd_stats ? formatJavaLikeDouble(flow.fwd_pkt_stats.stddev()) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.max) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.min) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.mean) : std::string("0")) << ','
        << (has_bwd_stats ? formatJavaLikeDouble(flow.bwd_pkt_stats.stddev()) : std::string("0")) << ','
        << formatJavaLikeDouble(flow.getFlowBytesPerSecond()) << ','
        << formatJavaLikeDouble(flow.getFlowPacketsPerSecond()) << ','
        << formatJavaLikeDouble(flow.flow_iat.mean) << ','
        << formatJavaLikeDouble(flow.flow_iat.stddev()) << ','
        << formatJavaLikeDouble(flow.flow_iat.n > 0 ? flow.flow_iat.max : 0.0) << ','
        << formatJavaLikeDouble(flow.flow_iat.n > 0 ? flow.flow_iat.min : 0.0) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.getFwdIATTotal()) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.getFwdIATMean()) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.getFwdIATStd()) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.getFwdIATMax()) : std::string("0")) << ','
        << (has_fwd_iat ? formatJavaLikeDouble(flow.getFwdIATMin()) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.getBwdIATTotal()) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.getBwdIATMean()) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.getBwdIATStd()) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.getBwdIATMax()) : std::string("0")) << ','
        << (has_bwd_iat ? formatJavaLikeDouble(flow.getBwdIATMin()) : std::string("0")) << ','
        << flow.f_psh_cnt << ','
        << flow.b_psh_cnt << ','
        << flow.f_urg_cnt << ','
        << flow.b_urg_cnt << ','
        << flow.f_header_bytes << ','
        << flow.b_header_bytes << ','
        << formatJavaLikeDouble(flow.getFwdPacketsPerSecond()) << ','
        << formatJavaLikeDouble(flow.getBwdPacketsPerSecond()) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.min) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.max) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.mean) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.stddev()) : std::string("0")) << ','
        << (has_pkt_len ? formatJavaLikeDouble(flow.flow_length_stats.variance()) : std::string("0")) << ','
        << flow.fin_flag_count << ','
        << flow.syn_flag_count << ','
        << flow.rst_flag_count << ','
        << flow.psh_flag_count << ','
        << flow.ack_flag_count << ','
        << flow.urg_flag_count << ','
        << flow.cwr_flag_count << ','
        << flow.ece_flag_count << ','
        << formatJavaLikeDouble(flow.getDownUpRatio()) << ','
        << formatJavaLikeDouble(flow.getAveragePacketSize()) << ','
        << formatJavaLikeDouble(flow.forward_packets > 0 ? flow.fwd_pkt_stats.sum / static_cast<double>(flow.forward_packets) : 0.0) << ','
        << formatJavaLikeDouble(flow.backward_packets > 0 ? flow.bwd_pkt_stats.sum / static_cast<double>(flow.backward_packets) : 0.0) << ','
        << flow.getFwdBytesPerBulkAvg() << ','
        << flow.getFwdPacketsPerBulkAvg() << ','
        << flow.getFwdBulkRateAvg() << ','
        << flow.getBwdBytesPerBulkAvg() << ','
        << flow.getBwdPacketsPerBulkAvg() << ','
        << flow.getBwdBulkRateAvg() << ','
        << flow.getSubflowFwdPackets() << ','
        << flow.getSubflowFwdBytes() << ','
        << flow.getSubflowBwdPackets() << ','
        << flow.getSubflowBwdBytes() << ','
        << flow.init_win_bytes_forward << ','
        << flow.init_win_bytes_backward << ','
        << flow.act_data_pkt_forward << ','
        << flow.min_seg_size_forward << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.mean) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.stddev()) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.max) : std::string("0")) << ','
        << (has_active ? formatJavaLikeDouble(flow.flow_active.min) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.mean) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.stddev()) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.max) : std::string("0")) << ','
        << (has_idle ? formatJavaLikeDouble(flow.flow_idle.min) : std::string("0")) << ','
        << "NeedManualLabel\n";

    return true;
}
