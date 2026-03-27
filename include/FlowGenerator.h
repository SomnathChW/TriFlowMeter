#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "BasicFlow.h"

class FlowGenerator {
private:
    struct FlowKey {
        std::array<std::uint8_t, 16> src{};
        std::array<std::uint8_t, 16> dst{};
        std::uint16_t src_port = 0;
        std::uint16_t dst_port = 0;
        std::uint8_t protocol = 0;
        std::uint8_t addr_len = 0;

        bool operator==(const FlowKey& other) const {
            return src == other.src &&
                   dst == other.dst &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port &&
                   protocol == other.protocol &&
                   addr_len == other.addr_len;
        }
    };

    struct FlowKeyHash {
        std::size_t operator()(const FlowKey& key) const noexcept {
            // FNV-1a over fixed fields keeps hashing fast and deterministic.
            std::size_t h = 1469598103934665603ULL;
            auto mix = [&h](std::uint8_t v) {
                h ^= static_cast<std::size_t>(v);
                h *= 1099511628211ULL;
            };

            for (std::uint8_t b : key.src) {
                mix(b);
            }
            for (std::uint8_t b : key.dst) {
                mix(b);
            }

            mix(static_cast<std::uint8_t>(key.src_port & 0xFF));
            mix(static_cast<std::uint8_t>((key.src_port >> 8) & 0xFF));
            mix(static_cast<std::uint8_t>(key.dst_port & 0xFF));
            mix(static_cast<std::uint8_t>((key.dst_port >> 8) & 0xFF));
            mix(key.protocol);
            mix(key.addr_len);
            return h;
        }
    };

    struct ActiveFlowEntry {
        BasicFlow flow;
        uint64_t insertion_order;
    };

    std::unordered_map<FlowKey, ActiveFlowEntry, FlowKeyHash> current_flows_;
    std::vector<BasicFlow> finished_flows_;
    std::function<void(const BasicFlow&)> flow_callback_;
    bool store_finished_flows_;
    int finished_flow_count_;
    uint64_t flow_timeout_;
    uint64_t activity_timeout_micros_;
    uint64_t next_insertion_order_;
    std::size_t peak_current_flows_;

    static FlowKey makeFlowKey(const BasicPacketInfo& pkt, bool forward);
    void handleFinishedFlow(const BasicFlow& flow);

public:
    explicit FlowGenerator(uint64_t timeout_sec = 120,
                           uint64_t activity_timeout_sec = 5);

    void addPacket(const BasicPacketInfo& pkt);
    void finishAllFlows();
    void setFlowCallback(std::function<void(const BasicFlow&)> callback);
    void setStoreFinishedFlows(bool store_finished_flows);

    int getFlowCount() const;
    int getCurrentFlowCount() const;
};
