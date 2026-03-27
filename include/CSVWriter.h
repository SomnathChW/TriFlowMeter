#pragma once

#include <ostream>

#include "BasicFlow.h"

class CSVWriter {
public:
    static void writeHeader(std::ostream& out);
    static bool writeFlowRow(std::ostream& out, const BasicFlow& flow);
};
