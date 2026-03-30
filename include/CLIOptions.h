#pragma once

/*
 * TriFlowMeter - High-Performance Network Flow Analyzer
 * Copyright (C) 2026 Somnath Chowdhury
 * Author: Somnath Chowdhury (http://github.com/SomnathChW)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
    std::string label = "Needs_Label";
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
