#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "BasicFlow.h"

class FlowGenerator {
private:
    struct ActiveFlowEntry {
        BasicFlow flow;
        uint64_t insertion_order;
    };

    std::unordered_map<std::string, ActiveFlowEntry> current_flows_;
    std::vector<BasicFlow> finished_flows_;
    uint64_t flow_timeout_;
    uint64_t next_insertion_order_;
    std::size_t peak_current_flows_;

public:
    explicit FlowGenerator(uint64_t timeout_sec = 120);

    void addPacket(const BasicPacketInfo& pkt);
    void finishAllFlows();
    const std::vector<BasicFlow>& getFinishedFlows() const;

    int getFlowCount() const;
    int getCurrentFlowCount() const;
};
