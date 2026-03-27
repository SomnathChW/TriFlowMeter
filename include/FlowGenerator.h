#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
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
    std::function<void(const BasicFlow&)> flow_callback_;
    bool store_finished_flows_;
    int finished_flow_count_;
    uint64_t flow_timeout_;
    uint64_t activity_timeout_micros_;
    uint64_t next_insertion_order_;
    std::size_t peak_current_flows_;

    void handleFinishedFlow(const BasicFlow& flow);

public:
    explicit FlowGenerator(uint64_t timeout_sec = 120,
                           uint64_t activity_timeout_sec = 5);

    void addPacket(const BasicPacketInfo& pkt);
    void finishAllFlows();
    const std::vector<BasicFlow>& getFinishedFlows() const;
    void setFlowCallback(std::function<void(const BasicFlow&)> callback);
    void setStoreFinishedFlows(bool store_finished_flows);

    int getFlowCount() const;
    int getCurrentFlowCount() const;
};
