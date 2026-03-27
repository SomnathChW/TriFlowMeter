#pragma once

#include <ostream>
#include <string>
#include <vector>

#include "BasicFlow.h"

class CSVWriter {
public:
    // Writes selected Java-compatible feature columns and returns row count, or -1 on failure.
    static int writeBasicFlowFeatures(const std::string& csv_path, const std::vector<BasicFlow>& flows);
    static void writeHeader(std::ostream& out);
    static bool writeFlowRow(std::ostream& out, const BasicFlow& flow);
};
