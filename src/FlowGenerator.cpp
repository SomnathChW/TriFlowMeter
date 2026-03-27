#include "FlowGenerator.h"

#include <algorithm>
#include <utility>

namespace {

uint32_t javaStringHash(const std::string& s) {
    uint32_t h = 0;
    for (unsigned char c : s) {
        h = 31U * h + static_cast<uint32_t>(c);
    }
    return h;
}

uint32_t javaSpreadHash(uint32_t h) {
    return h ^ (h >> 16);
}

std::size_t javaHashMapCapacityForPeakSize(std::size_t peak_size) {
    std::size_t cap = 16;
    std::size_t threshold = 12;
    while (peak_size > threshold) {
        cap <<= 1;
        threshold = (cap * 3) / 4;
    }
    return cap;
}

}  // namespace

FlowGenerator::FlowGenerator(uint64_t timeout_sec, uint64_t activity_timeout_sec) {
    flow_timeout_ = timeout_sec * 1000000;
    activity_timeout_micros_ = activity_timeout_sec * 1000000;
    store_finished_flows_ = true;
    finished_flow_count_ = 0;
    next_insertion_order_ = 0;
    peak_current_flows_ = 0;
}

void FlowGenerator::handleFinishedFlow(const BasicFlow& flow) {
    finished_flow_count_++;
    if (store_finished_flows_) {
        finished_flows_.push_back(flow);
    }
    if (flow_callback_) {
        flow_callback_(flow);
    }
}

void FlowGenerator::addPacket(const BasicPacketInfo& pkt) {
    const std::string fwd_id = pkt.fwdFlowId();
    const std::string bwd_id = pkt.bwdFlowId();
    std::string flow_id;

    bool found = false;
    auto fwd_it = current_flows_.find(fwd_id);
    auto bwd_it = current_flows_.find(bwd_id);
    if (fwd_it != current_flows_.end()) {
        flow_id = fwd_id;
        found = true;
    } else if (bwd_it != current_flows_.end()) {
        flow_id = bwd_id;
        found = true;
    }

    if (found) {
        auto it = current_flows_.find(flow_id);
        BasicFlow& flow = it->second.flow;
        const uint64_t flow_start = static_cast<uint64_t>(flow.start_time_sec) * 1000000 + flow.start_time_usec;
        const uint64_t pkt_time = static_cast<uint64_t>(pkt.timestamp_sec) * 1000000 + pkt.timestamp_usec;

        if ((pkt_time - flow_start) > flow_timeout_) {
            if (flow.packetCount() > 1) {
                handleFinishedFlow(flow);
            }
            current_flows_.erase(flow_id);
            ActiveFlowEntry entry{BasicFlow(pkt, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, activity_timeout_micros_), next_insertion_order_++};
            entry.flow.flow_id = flow_id;
            current_flows_.emplace(flow_id, std::move(entry));
            peak_current_flows_ = std::max(peak_current_flows_, current_flows_.size());
        } else {
            flow.addPacket(pkt);
            if (flow.finished) {
                handleFinishedFlow(flow);
                current_flows_.erase(flow_id);
            }
        }
    } else {
        ActiveFlowEntry entry{BasicFlow(pkt, activity_timeout_micros_), next_insertion_order_++};
        entry.flow.flow_id = fwd_id;
        current_flows_.emplace(fwd_id, std::move(entry));
        peak_current_flows_ = std::max(peak_current_flows_, current_flows_.size());
    }
}

void FlowGenerator::finishAllFlows() {
    if (current_flows_.empty()) {
        return;
    }

    struct FlushCandidate {
        std::size_t bucket;
        uint64_t insertion_order;
        const BasicFlow* flow;
    };

    const std::size_t cap = javaHashMapCapacityForPeakSize(peak_current_flows_);
    std::vector<FlushCandidate> pending;
    pending.reserve(current_flows_.size());

    for (const auto& pair : current_flows_) {
        const ActiveFlowEntry& entry = pair.second;
        if (entry.flow.packetCount() <= 1) {
            continue;
        }
        const uint32_t spread = javaSpreadHash(javaStringHash(pair.first));
        pending.push_back(FlushCandidate{static_cast<std::size_t>(spread & static_cast<uint32_t>(cap - 1)), entry.insertion_order, &entry.flow});
    }

    std::sort(pending.begin(), pending.end(), [](const FlushCandidate& a, const FlushCandidate& b) {
        if (a.bucket != b.bucket) {
            return a.bucket < b.bucket;
        }
        return a.insertion_order < b.insertion_order;
    });

    for (const auto& item : pending) {
        handleFinishedFlow(*item.flow);
    }

    current_flows_.clear();
}

void FlowGenerator::setFlowCallback(std::function<void(const BasicFlow&)> callback) {
    flow_callback_ = std::move(callback);
}

void FlowGenerator::setStoreFinishedFlows(bool store_finished_flows) {
    store_finished_flows_ = store_finished_flows;
    if (!store_finished_flows_) {
        finished_flows_.clear();
    }
}

int FlowGenerator::getFlowCount() const {
    return finished_flow_count_;
}

int FlowGenerator::getCurrentFlowCount() const {
    return static_cast<int>(current_flows_.size());
}
