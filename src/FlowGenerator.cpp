// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "FlowGenerator.h"

#include <algorithm>
#include <cstring>
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

FlowGenerator::FlowKey FlowGenerator::makeFlowKey(const BasicPacketInfo& pkt, bool forward) {
    FlowKey key;
    key.src_port = forward ? pkt.src_port : pkt.dst_port;
    key.dst_port = forward ? pkt.dst_port : pkt.src_port;
    key.protocol = pkt.protocol;
    key.addr_len = static_cast<std::uint8_t>(pkt.addr_len);

    const int len = pkt.addr_len > 16 ? 16 : pkt.addr_len;
    if (len > 0) {
        if (forward) {
            std::memcpy(key.src.data(), pkt.src_bytes, static_cast<std::size_t>(len));
            std::memcpy(key.dst.data(), pkt.dst_bytes, static_cast<std::size_t>(len));
        } else {
            std::memcpy(key.src.data(), pkt.dst_bytes, static_cast<std::size_t>(len));
            std::memcpy(key.dst.data(), pkt.src_bytes, static_cast<std::size_t>(len));
        }
    }

    return key;
}

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
    const FlowKey fwd_key = makeFlowKey(pkt, true);

    FlowKey matched_key = fwd_key;
    auto it = current_flows_.find(fwd_key);
    if (it == current_flows_.end()) {
        const FlowKey bwd_key = makeFlowKey(pkt, false);
        it = current_flows_.find(bwd_key);
        if (it != current_flows_.end()) {
            matched_key = bwd_key;
        }
    }

    if (it != current_flows_.end()) {
        BasicFlow& flow = it->second.flow;
        const uint64_t flow_start = static_cast<uint64_t>(flow.start_time_sec) * 1000000 + flow.start_time_usec;
        const uint64_t pkt_time = static_cast<uint64_t>(pkt.timestamp_sec) * 1000000 + pkt.timestamp_usec;

        if ((pkt_time - flow_start) > flow_timeout_) {
            const FlowKey existing_key = it->first;
            const std::string existing_flow_id = flow.flow_id;
            const std::string old_src_ip = flow.src_ip;
            const std::string old_dst_ip = flow.dst_ip;
            const uint16_t old_src_port = flow.src_port;
            const uint16_t old_dst_port = flow.dst_port;

            if (flow.packetCount() > 0) {
                handleFinishedFlow(flow);
            }

            current_flows_.erase(it);

            ActiveFlowEntry entry{BasicFlow(pkt, old_src_ip, old_dst_ip, old_src_port, old_dst_port, activity_timeout_micros_), next_insertion_order_++};
            entry.flow.flow_id = existing_flow_id;
            current_flows_.emplace(existing_key, std::move(entry));
            peak_current_flows_ = std::max(peak_current_flows_, current_flows_.size());
        } else {
            flow.addPacket(pkt);
            if (flow.finished) {
                handleFinishedFlow(flow);
                current_flows_.erase(it);
            }
        }
    } else {
        ActiveFlowEntry entry{BasicFlow(pkt, activity_timeout_micros_), next_insertion_order_++};
        entry.flow.flow_id = pkt.fwdFlowId();
        current_flows_.emplace(matched_key, std::move(entry));
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
        const uint32_t spread = javaSpreadHash(javaStringHash(entry.flow.flow_id));
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
