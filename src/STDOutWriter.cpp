// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "STDOutWriter.h"

#include <iostream>

#include "CSVWriter.h"

STDOutWriter::STDOutWriter(bool live_mode, const std::string& source_name)
    : live_mode_(live_mode), source_name_(source_name) {}

void STDOutWriter::announceCaptureStart() const {
    if (live_mode_) {
        std::cerr << "[+] Capturing live on interface: " << source_name_ << std::endl;
    } else {
        std::cerr << "[+] Reading pcap file: " << source_name_ << std::endl;
    }
}

void STDOutWriter::writeHeader() const {
    CSVWriter::writeHeader(std::cout);
}

bool STDOutWriter::writeFlowRow(const BasicFlow& flow) const {
    return CSVWriter::writeFlowRow(std::cout, flow);
}

void STDOutWriter::flush() const {
    std::cout.flush();
}
