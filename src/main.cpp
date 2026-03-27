#include <iostream>
#include <filesystem>
#include <string>
#include <cstdint>
#include <fstream>
#include <csignal>
#include <optional>

#include "FlowGenerator.h"
#include "CSVWriter.h"
#include "PacketReader.h"
#include "LiveDashboard.h"
#include "STDOutWriter.h"

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
    auto printUsage = [&argv]() {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " <pcap_file> [output_path_or_directory] [options]\n"
                  << "  " << argv[0] << " --live <interface> [output_path_or_directory] [options]\n"
                  << "Options:\n"
                  << "  --flow-timeout <sec>      Flow timeout in seconds (default: 120)\n"
                  << "  --activity-timeout <sec>  Activity timeout in seconds (default: 5)\n"
                  << "  --stdout                  Write CSV header/rows to stdout\n"
                  << "  -h, --help                Show this help" << std::endl;
    };

    if (argc < 2) {
        printUsage();
        return 1;
    }

    bool live_mode = false;
    bool stdout_mode = false;
    uint64_t flow_timeout_sec = 120;
    uint64_t activity_timeout_sec = 5;
    std::optional<std::string> capture_source_opt;
    std::optional<std::string> output_arg_opt;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage();
            return 0;
        }

        if (arg == "--live") {
            if (live_mode) {
                std::cerr << "Error: --live specified more than once." << std::endl;
                printUsage();
                return 1;
            }
            live_mode = true;
            continue;
        }

        if (arg == "--stdout") {
            if (stdout_mode) {
                std::cerr << "Error: --stdout specified more than once." << std::endl;
                printUsage();
                return 1;
            }
            stdout_mode = true;
            continue;
        }

        if (arg == "--flow-timeout") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --flow-timeout requires a value in seconds." << std::endl;
                printUsage();
                return 1;
            }
            try {
                flow_timeout_sec = std::stoull(argv[++i]);
            } catch (...) {
                std::cerr << "Error: --flow-timeout must be a non-negative integer." << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--activity-timeout") {
            if (i + 1 >= argc) {
                std::cerr << "Error: --activity-timeout requires a value in seconds." << std::endl;
                printUsage();
                return 1;
            }
            try {
                activity_timeout_sec = std::stoull(argv[++i]);
            } catch (...) {
                std::cerr << "Error: --activity-timeout must be a non-negative integer." << std::endl;
                return 1;
            }
            continue;
        }

        if (!capture_source_opt.has_value()) {
            capture_source_opt = arg;
        } else if (!output_arg_opt.has_value()) {
            output_arg_opt = arg;
        } else {
            std::cerr << "Error: Unexpected argument: " << arg << std::endl;
            printUsage();
            return 1;
        }
    }

    if (!capture_source_opt.has_value()) {
        std::cerr << "Error: Missing capture source." << std::endl;
        printUsage();
        return 1;
    }

    const std::string capture_source = *capture_source_opt;

    if (stdout_mode && output_arg_opt.has_value()) {
        std::cerr << "Error: output path cannot be used together with --stdout." << std::endl;
        printUsage();
        return 1;
    }

    const std::string* output_arg = nullptr;
    if (output_arg_opt.has_value()) {
        output_arg = &(*output_arg_opt);
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

    PacketStats stats;
    FlowGenerator flow_gen(flow_timeout_sec, activity_timeout_sec);
    std::uint64_t streamed_rows = 0;

    std::string csv_path;
    if (!stdout_mode) {
        csv_path = resolveCsvPath(capture_source, output_arg, !live_mode);
    }

    std::ofstream live_out;
    if (stdout_mode) {
        STDOutWriter stdout_writer(live_mode, capture_source);
        stdout_writer.announceCaptureStart();
        stdout_writer.writeHeader();
        stdout_writer.flush();

        flow_gen.setStoreFinishedFlows(false);
        flow_gen.setFlowCallback([&streamed_rows, &stdout_writer](const BasicFlow& flow) {
            if (stdout_writer.writeFlowRow(flow)) {
                streamed_rows++;
                stdout_writer.flush();
            }
        });

        if (!reader.readAll(flow_gen, stats, true, false, live_mode ? &g_stop_capture : nullptr, nullptr)) {
            std::cerr << "Error reading capture stream: " << reader.getLastError() << std::endl;
            return 1;
        }
    } else if (live_mode) {
        std::cout << "Capturing live on interface: " << capture_source
                  << " (continuous streaming mode)" << std::endl;

        LiveDashboard dashboard(capture_source, csv_path);

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
                [&dashboard, &flow_gen](const PacketStats& s) {
                    dashboard.setPacketStats(s);
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
        std::cout << "Reading pcap file: " << capture_source << std::endl;

        live_out.open(csv_path.c_str(), std::ios::out | std::ios::trunc);
        if (!live_out.is_open()) {
            std::cerr << "Error opening CSV output: " << csv_path << std::endl;
            return 1;
        }

        CSVWriter::writeHeader(live_out);
        live_out.flush();

        flow_gen.setStoreFinishedFlows(false);
        flow_gen.setFlowCallback([&live_out, &streamed_rows](const BasicFlow& flow) {
            if (CSVWriter::writeFlowRow(live_out, flow)) {
                streamed_rows++;
                live_out.flush();
            }
        });

        if (!reader.readAll(flow_gen, stats, true, false, nullptr, nullptr)) {
            std::cerr << "Error reading capture stream: " << reader.getLastError() << std::endl;
            return 1;
        }
    }

    flow_gen.finishAllFlows();

    int csv_rows = -1;
    if (stdout_mode) {
        csv_rows = static_cast<int>(streamed_rows);
    } else if (live_mode) {
        live_out.flush();
        csv_rows = static_cast<int>(streamed_rows);
    } else {
        live_out.flush();
        csv_rows = static_cast<int>(streamed_rows);
    }

    if (stdout_mode) {
        return 0;
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
