#pragma once

#include <string>
#include <vector>

#include "BasicFlow.h"

class InsertCsvRow {
public:
    // Writes selected Java-compatible feature columns and returns row count, or -1 on failure.
    static int writeBasicFlowFeatures(const std::string& csv_path, const std::vector<BasicFlow>& flows);
};
