#pragma once

#include <string>

#include "BasicFlow.h"

class STDOutWriter {
public:
    STDOutWriter(bool live_mode, const std::string& source_name);

    void announceCaptureStart() const;
    void writeHeader() const;
    bool writeFlowRow(const BasicFlow& flow) const;
    void flush() const;

private:
    bool live_mode_;
    std::string source_name_;
};
