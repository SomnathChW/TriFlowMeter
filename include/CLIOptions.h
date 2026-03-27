#pragma once

#include <cstdint>
#include <optional>
#include <string>

struct CLIOptions {
    bool live_mode = false;
    bool stdout_mode = false;
    std::uint64_t flow_timeout_sec = 120;
    std::uint64_t activity_timeout_sec = 5;
    std::string capture_source;
    std::optional<std::string> output_arg;
};

enum class CLIParseStatus {
    Ok,
    Help,
    Error,
};

struct CLIParseResult {
    CLIParseStatus status = CLIParseStatus::Error;
    CLIOptions options;
    std::string error;
};

std::string buildUsage(const std::string& program_name);
CLIParseResult parseCliArgs(int argc, char* argv[]);
std::string resolveCsvPath(const std::string& capture_source,
                           const std::optional<std::string>& output_arg,
                           bool use_legacy_offline_default);
