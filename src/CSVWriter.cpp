#include "CSVWriter.h"

#include <array>
#include <charconv>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {

std::string trimFixedLikeJava(std::string s) {
    const std::size_t dot = s.find('.');
    if (dot == std::string::npos) {
        return s + ".0";
    }

    while (!s.empty() && s.back() == '0') {
        s.pop_back();
    }
    if (!s.empty() && s.back() == '.') {
        s.push_back('0');
    }
    return s;
}

std::string normalizeExponentJavaStyle(std::string s) {
    std::size_t epos = s.find('e');
    if (epos == std::string::npos) {
        epos = s.find('E');
    }
    if (epos == std::string::npos) {
        return s;
    }

    std::string mant = s.substr(0, epos);
    std::string exp = s.substr(epos + 1);

    char sign = 0;
    if (!exp.empty() && (exp[0] == '+' || exp[0] == '-')) {
        sign = exp[0];
        exp.erase(0, 1);
    }

    while (exp.size() > 1 && exp[0] == '0') {
        exp.erase(0, 1);
    }

    std::string out = mant + "E";
    if (sign == '-') {
        out += '-';
    }
    out += exp;
    return out;
}

std::string scientificToPlain(std::string s) {
    std::size_t epos = s.find('E');
    if (epos == std::string::npos) {
        epos = s.find('e');
    }
    if (epos == std::string::npos) {
        return s;
    }

    std::string mant = s.substr(0, epos);
    std::string exp_str = s.substr(epos + 1);

    bool neg = false;
    if (!mant.empty() && mant[0] == '-') {
        neg = true;
        mant.erase(0, 1);
    } else if (!mant.empty() && mant[0] == '+') {
        mant.erase(0, 1);
    }

    int exp = 0;
    int sign = 1;
    std::size_t pos = 0;
    if (pos < exp_str.size() && (exp_str[pos] == '+' || exp_str[pos] == '-')) {
        sign = (exp_str[pos] == '-') ? -1 : 1;
        ++pos;
    }
    for (; pos < exp_str.size(); ++pos) {
        const char c = exp_str[pos];
        if (c < '0' || c > '9') {
            break;
        }
        exp = exp * 10 + (c - '0');
    }
    exp *= sign;

    std::string digits;
    int digits_before_dot = 0;
    const std::size_t dot = mant.find('.');
    if (dot == std::string::npos) {
        digits = mant;
        digits_before_dot = static_cast<int>(digits.size());
    } else {
        digits = mant.substr(0, dot) + mant.substr(dot + 1);
        digits_before_dot = static_cast<int>(dot);
    }

    if (digits.empty()) {
        return neg ? "-0.0" : "0.0";
    }

    int decimal_index = digits_before_dot + exp;
    std::string out;
    if (decimal_index <= 0) {
        out = "0.";
        out.append(static_cast<std::size_t>(-decimal_index), '0');
        out += digits;
    } else if (decimal_index >= static_cast<int>(digits.size())) {
        out = digits;
        out.append(static_cast<std::size_t>(decimal_index - static_cast<int>(digits.size())), '0');
    } else {
        out = digits.substr(0, static_cast<std::size_t>(decimal_index));
        out += '.';
        out += digits.substr(static_cast<std::size_t>(decimal_index));
    }

    out = trimFixedLikeJava(out);
    if (neg && out != "0.0") {
        out.insert(out.begin(), '-');
    }
    return out;
}

std::string formatJavaLikeDouble(double value) {
    if (std::isnan(value)) {
        return "NaN";
    }
    if (std::isinf(value)) {
        return value > 0 ? "Infinity" : "-Infinity";
    }

    std::array<char, 128> buffer{};
    std::string out;
    auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, std::chars_format::general);
    if (result.ec == std::errc()) {
        out.assign(buffer.data(), result.ptr);
    } else {
        std::ostringstream oss;
        oss.setf(std::ios::fmtflags(0), std::ios::floatfield);
        oss.precision(17);
        oss << value;
        out = oss.str();
    }

    const double abs_value = std::fabs(value);
    const bool use_plain = (abs_value == 0.0) || (abs_value >= 1e-3 && abs_value < 1e7);
    if (use_plain && (out.find('e') != std::string::npos || out.find('E') != std::string::npos)) {
        out = scientificToPlain(out);
    } else {
        out = normalizeExponentJavaStyle(out);
    }

    // Java-style CSV often shows whole-number doubles as x.0.
    if (out.find('.') == std::string::npos && out.find('e') == std::string::npos && out.find('E') == std::string::npos) {
        out += ".0";
    }

    return out;
}

}  // namespace

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
    if (flow.packetCount() <= 1) {
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

int CSVWriter::writeBasicFlowFeatures(const std::string& csv_path, const std::vector<BasicFlow>& flows) {
    std::ofstream out(csv_path.c_str(), std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        return -1;
    }

    writeHeader(out);

    int rows = 0;
    for (const auto& flow : flows) {
        if (writeFlowRow(out, flow)) {
            rows++;
        }
    }

    return rows;
}
