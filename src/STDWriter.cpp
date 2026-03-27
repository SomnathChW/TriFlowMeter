#include "STDWriter.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace {

constexpr int kDashboardLines = 7;
constexpr int kDashboardMove = kDashboardLines - 1;

constexpr std::size_t kOuterInnerWidth = 80;
constexpr std::size_t kCol1Width = 24;
constexpr std::size_t kCol2Width = 24;
constexpr std::size_t kCol3Width = 30;
constexpr std::size_t kFooterLeftWidth = 24;
constexpr std::size_t kFooterRightWidth = 55;

std::string hline(std::size_t inner_width) {
    return std::string("+") + std::string(inner_width, '-') + "+";
}

std::string colSeparator(std::size_t c1, std::size_t c2, std::size_t c3) {
    return std::string("+") + std::string(c1, '-') + "+" + std::string(c2, '-') + "+" + std::string(c3, '-') + "+";
}

std::string colSeparator(std::size_t c1, std::size_t c2) {
    return std::string("+") + std::string(c1, '-') + "+" + std::string(c2, '-') + "+";
}

const std::vector<std::string>& bannerLines() {
    static const std::vector<std::string> kBanner = {
        "████████╗██████╗ ██╗███████╗██╗      ██████╗ ██╗    ██╗",
        "╚══██╔══╝██╔══██╗██║██╔════╝██║     ██╔═══██╗██║    ██║",
        "   ██║   ██████╔╝██║█████╗  ██║     ██║   ██║██║ █╗ ██║",
        "   ██║   ██╔══██╗██║██╔══╝  ██║     ██║   ██║██║███╗██║",
        "   ██║   ██║  ██║██║██║     ███████╗╚██████╔╝╚███╔███╔╝",
        "   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ",
        "       ███╗   ███╗███████╗████████╗███████╗██████╗ ",
        "       ████╗ ████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗",
        "       ██╔████╔██║█████╗     ██║   █████╗  ██████╔╝",
        "       ██║╚██╔╝██║██╔══╝     ██║   ██╔══╝  ██╔══██╗",
        "       ██║ ╚═╝ ██║███████╗   ██║   ███████╗██║  ██║",
        "       ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    };
    return kBanner;
}

}

STDWriter::STDWriter(const std::string& title,
                     const std::string& source_name,
                     const std::string& output_path)
    : title_(title),
      source_name_(source_name),
      output_path_(output_path),
      start_time_(std::chrono::steady_clock::now()),
      last_refresh_time_(start_time_) {}

void STDWriter::setPacketStats(const PacketStats& stats) {
    stats_ = stats;
}

void STDWriter::setWrittenFlows(std::uint64_t flows) {
    written_flows_ = flows;
}

void STDWriter::setActiveFlows(std::uint64_t flows) {
    active_flows_ = flows;
}

void STDWriter::refreshIfDue() {
    const auto now = std::chrono::steady_clock::now();
    if (now - last_refresh_time_ >= std::chrono::seconds(1)) {
        render();
        last_refresh_time_ = now;
    }
}

void STDWriter::forceRefresh() {
    render();
    last_refresh_time_ = std::chrono::steady_clock::now();
}

void STDWriter::finalize() {
    if (initialized_) {
        std::cout << "\033[" << kDashboardMove << "B\r" << std::endl;
    }
}

std::string STDWriter::shortCount(long long value) {
    std::ostringstream oss;
    if (value >= 1000000000LL) {
        oss << std::fixed << std::setprecision(1) << (static_cast<double>(value) / 1000000000.0) << "G";
    } else if (value >= 1000000LL) {
        oss << std::fixed << std::setprecision(1) << (static_cast<double>(value) / 1000000.0) << "M";
    } else if (value >= 1000LL) {
        oss << std::fixed << std::setprecision(1) << (static_cast<double>(value) / 1000.0) << "K";
    } else {
        oss << value;
    }

    std::string s = oss.str();
    if (s.size() > 2 && s.find('.') != std::string::npos && s.back() == '0') {
        s.erase(s.size() - 2, 1);
    }
    return s;
}

std::string STDWriter::clip(const std::string& s, std::size_t width) {
    if (s.size() <= width) {
        return s;
    }
    if (width <= 3) {
        return s.substr(0, width);
    }
    return s.substr(0, width - 3) + "...";
}

std::string STDWriter::makeRow(const std::string& content, std::size_t inner_width) {
    std::string row = clip(content, inner_width);
    if (row.size() < inner_width) {
        row.append(inner_width - row.size(), ' ');
    }
    return "|" + row + "|";
}

void STDWriter::render() {
    const auto now = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();

    const long long hh = elapsed / 3600;
    const long long mm = (elapsed % 3600) / 60;
    const long long ss = elapsed % 60;

    std::ostringstream tss;
    tss << std::setfill('0') << std::setw(2) << hh << ':'
        << std::setfill('0') << std::setw(2) << mm << ':'
        << std::setfill('0') << std::setw(2) << ss;

    auto makeCell = [&](const std::string& content, std::size_t width) {
        std::string c = clip(content, width);
        if (c.size() < width) {
            c.append(width - c.size(), ' ');
        }
        return c;
    };

    const std::string line1 = hline(kOuterInnerWidth);

    const std::string line2 =
        "|" + makeCell(" Source: " + source_name_, kCol1Width) +
        "|" + makeCell(" Uptime: " + tss.str(), kCol2Width) +
        "|" + makeCell(" Packets: " + shortCount(stats_.total), kCol3Width) + "|";

    const std::string line3 = colSeparator(kCol1Width, kCol2Width, kCol3Width);

    const std::string line4 =
        "|" + makeCell(" Valid: " + shortCount(stats_.valid), kCol1Width) +
        "|" + makeCell(" Discarded: " + shortCount(stats_.discarded), kCol2Width) +
        "|" + makeCell(" Written Flows: " + shortCount(static_cast<long long>(written_flows_)), kCol3Width) + "|";

    const std::string line5 = colSeparator(kFooterLeftWidth, kFooterRightWidth);
    const std::string line6 =
        "|" + makeCell(" Active Flows: " + shortCount(static_cast<long long>(active_flows_)), kFooterLeftWidth) +
        "|" + makeCell(" CSV Output: " + output_path_, kFooterRightWidth) + "|";
    const std::string line7 = hline(kOuterInnerWidth);

    if (!initialized_) {
        for (const auto& line : bannerLines()) {
            std::cout << line << std::endl;
        }
        initialized_ = true;
    }

    std::cout << "\r\033[2K" << line1
              << "\n\033[2K" << line2
              << "\n\033[2K" << line3
              << "\n\033[2K" << line4
              << "\n\033[2K" << line5
              << "\n\033[2K" << line6
              << "\n\033[2K" << line7
              << "\033[" << kDashboardMove << "A" << std::flush;
}
