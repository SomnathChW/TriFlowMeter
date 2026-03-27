#include <iostream>
#include <filesystem>
#include <string>
#include <cstdint>
#include <fstream>
#include <csignal>

#include "FlowGenerator.h"
#include "CSVWriter.h"
#include "PacketReader.h"
#include "STDWriter.h"

namespace {

namespace fs = std::filesystem;

volatile std::sig_atomic_t g_stop_capture = 0;

void handleSignal(int) {
    g_stop_capture = 1;
}

std::string stemFromCaptureSource(const std::string& source) {
    const fs::path p(source);
    std::string stem = p.stem().string();
    if (stem.empty()) {
        stem = p.filename().string();
    }
    if (stem.empty()) {
        stem = "capture";
    }
    return stem;
}

std::string deriveLegacyOfflineCsvPath(const std::string& source) {
    return stemFromCaptureSource(source) + "_Flow.csv";
}

std::string deriveModernCsvPathFromStem(const std::string& stem) {
    return stem + "_flows.csv";
}

std::string deriveCsvPathInDirectory(const std::string& stem, const std::string& directory) {
    fs::path out_dir(directory);

    if (!out_dir.empty()) {
        fs::create_directories(out_dir);
    }

    const fs::path out_file = out_dir / (stem + "_flows.csv");
    return out_file.string();
}

std::string resolveCsvPath(const std::string& capture_source,
                           const std::string* output_arg,
                           bool use_legacy_offline_default) {
    const std::string stem = stemFromCaptureSource(capture_source);

    if (output_arg == nullptr) {
        if (use_legacy_offline_default) {
            return deriveLegacyOfflineCsvPath(capture_source);
        }
        return deriveModernCsvPathFromStem(stem);
    }

    const fs::path out_path(*output_arg);
    const std::string out_raw = out_path.string();
    const bool trailing_separator = !out_raw.empty() &&
        (out_raw.back() == '/' || out_raw.back() == '\\');

    if (trailing_separator || (fs::exists(out_path) && fs::is_directory(out_path))) {
        return deriveCsvPathInDirectory(stem, out_raw);
    }

    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path());
    }
    return out_path.string();
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " <pcap_file> [output_path_or_directory]\n"
                  << "  " << argv[0] << " --live <interface> [output_path_or_directory]"
                  << std::endl;
        return 1;
    }

    bool live_mode = false;
    std::string capture_source;

    std::string output_arg_value;
    const std::string* output_arg = nullptr;

    if (std::string(argv[1]) == "--live") {
        if (argc < 3 || argc > 4) {
            std::cerr << "Usage: " << argv[0]
                      << " --live <interface> [output_path_or_directory]" << std::endl;
            return 1;
        }

        live_mode = true;
        capture_source = argv[2];
        if (argc == 4) {
            output_arg_value = argv[3];
            output_arg = &output_arg_value;
        }
    } else {
        if (argc > 3) {
            std::cerr << "Usage: " << argv[0] << " <pcap_file> [output_path_or_directory]" << std::endl;
            return 1;
        }
        capture_source = argv[1];
        if (argc == 3) {
            output_arg_value = argv[2];
            output_arg = &output_arg_value;
        }
    }

    PacketReader reader = live_mode
        ? PacketReader(PacketReader::Mode::Live, capture_source, 65535, true, 1000)
        : PacketReader(capture_source);

    if (live_mode) {
        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);
    }

    if (!reader.open()) {
        std::cerr << "Error opening capture source: " << reader.getLastError() << std::endl;
        return 1;
    }

    if (live_mode) {
        std::cout << "Capturing live on interface: " << capture_source
                  << " (continuous streaming mode)" << std::endl;
    } else {
        std::cout << "Reading pcap file: " << capture_source << std::endl;
    }

    PacketStats stats;
    FlowGenerator flow_gen(120);
    std::uint64_t streamed_rows = 0;

    const std::string csv_path = resolveCsvPath(capture_source, output_arg, !live_mode);

    std::ofstream live_out;
    if (live_mode) {
        PacketStats live_stats_snapshot;
        STDWriter dashboard("Interface", capture_source, csv_path);

        live_out.open(csv_path.c_str(), std::ios::out | std::ios::trunc);
        if (!live_out.is_open()) {
            std::cerr << "Error opening CSV output: " << csv_path << std::endl;
            return 1;
        }

        CSVWriter::writeHeader(live_out);
        live_out.flush();
        flow_gen.setStoreFinishedFlows(false);
        flow_gen.setFlowCallback([&live_out, &streamed_rows, &dashboard, &flow_gen](const BasicFlow& flow) {
            if (CSVWriter::writeFlowRow(live_out, flow)) {
                streamed_rows++;
                live_out.flush();
                dashboard.setWrittenFlows(streamed_rows);
                dashboard.setActiveFlows(static_cast<std::uint64_t>(flow_gen.getCurrentFlowCount()));
                dashboard.refreshIfDue();
            }
        });

        dashboard.forceRefresh();

        if (!reader.readAll(
                flow_gen,
                stats,
                true,
                false,
                live_mode ? &g_stop_capture : nullptr,
                [&live_stats_snapshot, &dashboard, &flow_gen](const PacketStats& s) {
                    live_stats_snapshot = s;
                    dashboard.setPacketStats(live_stats_snapshot);
                    dashboard.setActiveFlows(static_cast<std::uint64_t>(flow_gen.getCurrentFlowCount()));
                    dashboard.refreshIfDue();
                })) {
            std::cerr << "Error reading capture stream: " << reader.getLastError() << std::endl;
            return 1;
        }

        dashboard.setPacketStats(stats);
        dashboard.setWrittenFlows(streamed_rows);
        dashboard.setActiveFlows(static_cast<std::uint64_t>(flow_gen.getCurrentFlowCount()));
        dashboard.forceRefresh();
        dashboard.finalize();
    } else {
        if (!reader.readAll(flow_gen, stats, true, false, nullptr, nullptr)) {
            std::cerr << "Error reading capture stream: " << reader.getLastError() << std::endl;
            return 1;
        }
    }

    flow_gen.finishAllFlows();

    int csv_rows = -1;
    if (live_mode) {
        live_out.flush();
        csv_rows = static_cast<int>(streamed_rows);
    } else {
        csv_rows = CSVWriter::writeBasicFlowFeatures(csv_path, flow_gen.getFinishedFlows());
    }

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
