// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (C) 2026 | Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "CLIOptions.h"
#include "FileUtils.h"

#include <filesystem>

namespace {

namespace fs = std::filesystem;

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
        fixOwnershipIfSudo(out_dir.string(), true);
    }

    const fs::path out_file = out_dir / (stem + "_flows.csv");
    return out_file.string();
}

}  // namespace

std::string buildUsage(const std::string& program_name) {
    return "Usage:\n"
           "  " + program_name + " <pcap_file> [output_path_or_directory] [options]\n"
           "  " + program_name + " --live <interface> [output_path_or_directory] [options]\n"
           "Options:\n"
           "  --flow-timeout <sec>      Flow timeout in seconds (default: 120)\n"
           "  --activity-timeout <sec>  Activity timeout in seconds (default: 5)\n"
           "  --stdout                  Write CSV header/rows to stdout\n"
           "  -h, --help                Show this help";
}

CLIParseResult parseCliArgs(int argc, char* argv[]) {
    CLIParseResult result;

    if (argc < 2) {
        result.status = CLIParseStatus::Error;
        result.error = "Missing arguments.";
        return result;
    }

    bool capture_seen = false;
    bool output_seen = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            result.status = CLIParseStatus::Help;
            return result;
        }

        if (arg == "--live") {
            if (result.options.live_mode) {
                result.status = CLIParseStatus::Error;
                result.error = "--live specified more than once.";
                return result;
            }
            result.options.live_mode = true;
            continue;
        }

        if (arg == "--stdout") {
            if (result.options.stdout_mode) {
                result.status = CLIParseStatus::Error;
                result.error = "--stdout specified more than once.";
                return result;
            }
            result.options.stdout_mode = true;
            continue;
        }

        if (arg == "--flow-timeout") {
            if (i + 1 >= argc) {
                result.status = CLIParseStatus::Error;
                result.error = "--flow-timeout requires a value in seconds.";
                return result;
            }
            try {
                result.options.flow_timeout_sec = std::stoull(argv[++i]);
            } catch (...) {
                result.status = CLIParseStatus::Error;
                result.error = "--flow-timeout must be a non-negative integer.";
                return result;
            }
            continue;
        }

        if (arg == "--activity-timeout") {
            if (i + 1 >= argc) {
                result.status = CLIParseStatus::Error;
                result.error = "--activity-timeout requires a value in seconds.";
                return result;
            }
            try {
                result.options.activity_timeout_sec = std::stoull(argv[++i]);
            } catch (...) {
                result.status = CLIParseStatus::Error;
                result.error = "--activity-timeout must be a non-negative integer.";
                return result;
            }
            continue;
        }

        if (!capture_seen) {
            result.options.capture_source = arg;
            capture_seen = true;
            continue;
        }

        if (!output_seen) {
            result.options.output_arg = arg;
            output_seen = true;
            continue;
        }

        result.status = CLIParseStatus::Error;
        result.error = "Unexpected argument: " + arg;
        return result;
    }

    if (!capture_seen) {
        result.status = CLIParseStatus::Error;
        result.error = "Missing capture source.";
        return result;
    }

    if (result.options.stdout_mode && result.options.output_arg.has_value()) {
        result.status = CLIParseStatus::Error;
        result.error = "output path cannot be used together with --stdout.";
        return result;
    }

    result.status = CLIParseStatus::Ok;
    return result;
}

std::string resolveCsvPath(const std::string& capture_source,
                           const std::optional<std::string>& output_arg,
                           bool use_legacy_offline_default) {
    const std::string stem = stemFromCaptureSource(capture_source);

    if (!output_arg.has_value()) {
        if (use_legacy_offline_default) {
            return deriveLegacyOfflineCsvPath(capture_source);
        }
        return deriveModernCsvPathFromStem(stem);
    }

    const fs::path out_path(*output_arg);
    const std::string out_raw = out_path.string();
    const bool trailing_separator = !out_raw.empty() &&
        (out_raw.back() == '/' || out_raw.back() == '\\');

    // Check if it's a directory: has trailing slash, exists as directory, or has no extension
    const bool looks_like_directory = trailing_separator || 
                                      (fs::exists(out_path) && fs::is_directory(out_path)) ||
                                      out_path.extension().empty();

    if (looks_like_directory) {
        return deriveCsvPathInDirectory(stem, out_raw);
    }

    if (out_path.has_parent_path()) {
        fs::create_directories(out_path.parent_path());
        fixOwnershipIfSudo(out_path.parent_path().string(), true);
    }
    return out_path.string();
}
