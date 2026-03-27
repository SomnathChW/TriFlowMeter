#include <iostream>
#include <string>
#include <cstdint>
#include <fstream>
#include <csignal>

#include "CLIOptions.h"
#include "FlowGenerator.h"
#include "CSVWriter.h"
#include "PacketReader.h"
#include "LiveDashboard.h"
#include "STDOutWriter.h"

namespace {

volatile std::sig_atomic_t g_stop_capture = 0;

void handleSignal(int) {
    g_stop_capture = 1;
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string usage = buildUsage(argc > 0 ? argv[0] : "triflowmeter");
    const CLIParseResult cli = parseCliArgs(argc, argv);
    if (cli.status == CLIParseStatus::Help) {
        std::cerr << usage << std::endl;
        return 0;
    }
    if (cli.status == CLIParseStatus::Error) {
        std::cerr << "Error: " << cli.error << std::endl;
        std::cerr << usage << std::endl;
        return 1;
    }

    const CLIOptions& opts = cli.options;
    const std::string& capture_source = opts.capture_source;

    PacketReader reader = opts.live_mode
        ? PacketReader(PacketReader::Mode::Live, capture_source, 65535, true, 1000)
        : PacketReader(capture_source);

    if (opts.live_mode) {
        std::signal(SIGINT, handleSignal);
        std::signal(SIGTERM, handleSignal);
    }

    if (!reader.open()) {
        std::cerr << "Error opening capture source: " << reader.getLastError() << std::endl;
        return 1;
    }

    PacketStats stats;
    FlowGenerator flow_gen(opts.flow_timeout_sec, opts.activity_timeout_sec);
    std::uint64_t streamed_rows = 0;

    std::string csv_path;
    if (!opts.stdout_mode) {
        csv_path = resolveCsvPath(capture_source, opts.output_arg, !opts.live_mode);
    }

    std::ofstream live_out;
    if (opts.stdout_mode) {
        STDOutWriter stdout_writer(opts.live_mode, capture_source);
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

        if (!reader.readAll(flow_gen, stats, true, false, opts.live_mode ? &g_stop_capture : nullptr, nullptr)) {
            std::cerr << "Error reading capture stream: " << reader.getLastError() << std::endl;
            return 1;
        }
    } else if (opts.live_mode) {
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
                opts.live_mode ? &g_stop_capture : nullptr,
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
    if (opts.stdout_mode) {
        csv_rows = static_cast<int>(streamed_rows);
    } else if (opts.live_mode) {
        live_out.flush();
        csv_rows = static_cast<int>(streamed_rows);
    } else {
        live_out.flush();
        csv_rows = static_cast<int>(streamed_rows);
    }

    if (opts.stdout_mode) {
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
