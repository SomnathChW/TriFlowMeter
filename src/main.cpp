#include <iostream>
#include <filesystem>
#include <string>

#include "FlowGenerator.h"
#include "InsertCsvRow.h"
#include "PacketReader.h"

namespace {

namespace fs = std::filesystem;

std::string deriveCsvPath(const std::string& pcap_path) {
    std::string base = pcap_path;
    const std::string::size_type slash_pos = base.find_last_of("/\\");
    if (slash_pos != std::string::npos) {
        base = base.substr(slash_pos + 1);
    }

    const std::string::size_type dot_pos = base.find_last_of('.');
    if (dot_pos != std::string::npos) {
        base = base.substr(0, dot_pos);
    }

    return base + "_Flow.csv";
}

std::string deriveCsvPathInDirectory(const std::string& pcap_path, const std::string& directory) {
    const fs::path pcap_fs_path(pcap_path);
    const std::string stem = pcap_fs_path.stem().string();
    fs::path out_dir(directory);

    if (!out_dir.empty()) {
        fs::create_directories(out_dir);
    }

    const fs::path out_file = out_dir / (stem + "_flows.csv");
    return out_file.string();
}

std::string resolveCsvPath(const std::string& pcap_path, const std::string* output_arg) {
    if (output_arg == nullptr) {
        return deriveCsvPath(pcap_path);
    }

    const fs::path out_path(*output_arg);
    const std::string out_raw = out_path.string();
    const bool trailing_separator = !out_raw.empty() &&
        (out_raw.back() == '/' || out_raw.back() == '\\');

    if (trailing_separator || (fs::exists(out_path) && fs::is_directory(out_path))) {
        return deriveCsvPathInDirectory(pcap_path, out_raw);
    }

    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path());
    }
    return out_path.string();
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2 || argc > 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file> [output_path_or_directory]" << std::endl;
        return 1;
    }

    const std::string pcap_file = argv[1];
    std::string output_arg_value;
    const std::string* output_arg = nullptr;
    if (argc == 3) {
        output_arg_value = argv[2];
        output_arg = &output_arg_value;
    }
    PacketReader reader(pcap_file);
    if (!reader.open()) {
        std::cerr << "Error opening pcap file: " << reader.getLastError() << std::endl;
        return 1;
    }

    std::cout << "Reading pcap file: " << pcap_file << std::endl;

    PacketStats stats;
    FlowGenerator flow_gen(120);
    if (!reader.readAll(flow_gen, stats, true, false)) {
        std::cerr << "Error reading pcap file: " << reader.getLastError() << std::endl;
        return 1;
    }

    flow_gen.finishAllFlows();

    const std::string csv_path = resolveCsvPath(pcap_file, output_arg);
    const int csv_rows = InsertCsvRow::writeBasicFlowFeatures(csv_path, flow_gen.getFinishedFlows());

    std::cout << "\n=== Packet Statistics ===" << std::endl;
    std::cout << "Total packets:     " << stats.total << std::endl;
    std::cout << "Valid packets:     " << stats.valid << std::endl;
    std::cout << "Discarded packets: " << stats.discarded << std::endl;
    if (stats.vpn_packets > 0) {
        std::cout << "VPN/L2TP packets:  " << stats.vpn_packets << std::endl;
    }

    std::cout << "\n=== Flow Statistics ===" << std::endl;
    std::cout << "Total flows:       " << flow_gen.getFlowCount() << std::endl;
    if (csv_rows >= 0) {
        std::cout << "CSV:               " << csv_path << " (" << csv_rows << " rows)" << std::endl;
    } else {
        std::cout << "CSV:               failed to write " << csv_path << std::endl;
    }

    return 0;
}
