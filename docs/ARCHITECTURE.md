<!--
TriFlowMeter - High-Performance Network Flow Analyzer
Copyright (C) 2026 Somnath Chowdhury
Author: Somnath Chowdhury (http://github.com/SomnathChW)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->

# TriFlowMeter Architecture

This document provides in-depth architectural documentation for TriFlowMeter, explaining the flow lifecycle, packet processing pipeline, and internal algorithms.

## Table of Contents

1. [System Overview](#system-overview)
2. [Flow Lifecycle](#flow-lifecycle)
3. [Packet Processing Pipeline](#packet-processing-pipeline)
4. [Flow Creation](#flow-creation)
5. [Packet Assignment to Flows](#packet-assignment-to-flows)
6. [Flow Timeout and Termination](#flow-timeout-and-termination)
7. [Flow Splitting](#flow-splitting)
8. [Bidirectional Flow Tracking](#bidirectional-flow-tracking)
9. [Statistical Computation](#statistical-computation)
10. [Data Structures](#data-structures)
11. [Performance Optimizations](#performance-optimizations)

---

## System Overview

TriFlowMeter follows a pipeline architecture with the following components:

```
┌──────────────┐    ┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│   Packet     │───▶│   Packet     │───▶│     Flow      │───▶│   Feature    │
│   Reader     │    │   Decoder    │    │   Generator   │    │  Extraction  │
└──────────────┘    └──────────────┘    └───────────────┘    └──────────────┘
                                                │
                                                ▼
                                        ┌───────────────┐
                                        │  CSV Writer   │
                                        └───────────────┘
```

### Core Components

1. **PacketReader** (`PacketReader.h/cpp`): Captures packets from PCAP files or live interfaces using libpcap
2. **PacketDecoders** (`PacketDecoders.h/cpp`): Parses Ethernet, IP, TCP, UDP headers and extracts packet metadata
3. **FlowGenerator** (`FlowGenerator.h/cpp`): Aggregates packets into bidirectional flows
4. **BasicFlow** (`BasicFlow.h/cpp`): Represents a single network flow with statistical features
5. **CSVWriter** (`CSVWriter.h/cpp`): Serializes flow features to CSV format

---

## Flow Lifecycle

A network flow in TriFlowMeter progresses through several states:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Created   │────▶│   Active    │────▶│  Finishing  │────▶│  Exported   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                    │                    │
      │                    │                    │
      └────────────────────┴────────────────────┘
                   (Timeout / RST)
```

### States

1. **Created**: Flow is instantiated when the first packet is encountered
2. **Active**: Flow receives and processes subsequent packets
3. **Finishing**: Flow is marked for termination (FIN flags, RST, timeout)
4. **Exported**: Flow statistics are written to CSV and removed from memory

---

## Packet Processing Pipeline

Each packet undergoes the following processing stages:

### 1. Packet Capture

- **Source**: PCAP file or live network interface
- **Library**: libpcap
- **Output**: Raw packet data with timestamp

### 2. Packet Decoding

```cpp
// PacketDecoders.cpp: parsePacket()
Ethernet Frame
    └─▶ IP Header (IPv4/IPv6)
         └─▶ Transport Header (TCP/UDP)
              └─▶ Payload
```

**Extracted Information**:

- Source/Destination IP addresses (IPv4/IPv6)
- Source/Destination ports
- Protocol (TCP=6, UDP=17)
- Timestamp (seconds + microseconds)
- Payload size
- Header size
- TCP flags (SYN, ACK, FIN, RST, PSH, URG, CWR, ECE)
- TCP window size

### 3. Flow Assignment

The packet is matched to an existing flow or creates a new one (detailed in next section).

### 4. Feature Computation

Real-time statistical updates:

- Running statistics (mean, variance, min, max)
- Inter-arrival times
- Flag counters
- Bulk transfer detection
- Subflow tracking

---

## Flow Creation

### When Flows are Created

A new flow is created when:

1. **First packet from a new 5-tuple** arrives
2. **Flow timeout expires** and a new packet arrives for the same 5-tuple (flow splits)

### Flow Initialization

```cpp
// BasicFlow.cpp: Constructor
BasicFlow::BasicFlow(const BasicPacketInfo& pkt, uint64_t activity_timeout) {
    // Set flow identifiers
    flow_id = pkt.fwdFlowId();  // src_ip-dst_ip-src_port-dst_port-protocol
    src_ip = pkt.src_ip;
    dst_ip = pkt.dst_ip;
    src_port = pkt.src_port;
    dst_port = pkt.dst_port;
    protocol = pkt.protocol;

    // Initialize timestamps
    start_time_sec = pkt.timestamp_sec;
    start_time_usec = pkt.timestamp_usec;
    flow_start_time = toMicros(pkt.timestamp_sec, pkt.timestamp_usec);

    // Process first packet
    // - Determine direction (forward/backward)
    // - Update packet counters
    // - Initialize statistics
    // - Check TCP flags
}
```

### Flow Identification

**Flow ID Format**: `{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}`

**Bidirectional Matching**:

- Forward key: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Backward key: `(dst_ip, src_ip, dst_port, src_port, protocol)`

Both directions map to the same flow.

---

## Packet Assignment to Flows

### Flow Key Generation

```cpp
// FlowGenerator.cpp: makeFlowKey()
FlowKey {
    array<uint8_t, 16> src;    // IP address bytes
    array<uint8_t, 16> dst;    // IP address bytes
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t addr_len;          // 4 for IPv4, 16 for IPv6
}
```

### Lookup Process

```cpp
// FlowGenerator.cpp: addPacket()
1. Generate forward flow key from packet
2. Search hash table for forward key
3. If not found:
   a. Generate backward flow key
   b. Search hash table for backward key
4. If found (forward or backward):
   a. Check flow timeout
   b. If timeout exceeded → split flow
   c. Else → add packet to existing flow
5. If not found:
   a. Create new flow
   b. Insert into hash table with forward key
```

### Hash Table

- **Type**: `std::unordered_map<FlowKey, ActiveFlowEntry>`
- **Hash Function**: FNV-1a hash over flow key fields
- **Collision Resolution**: Chaining (standard library)

---

## Flow Timeout and Termination

### Timeout Types

#### 1. Flow Timeout (Default: 120 seconds)

- **Purpose**: Split long-lived flows into manageable segments
- **Trigger**: `(packet_time - flow_start_time) > flow_timeout`
- **Action**:
    1. Export current flow if packet count > 1
    2. Create new flow with same 5-tuple
    3. Preserve flow ID for continuity

```cpp
// FlowGenerator.cpp: addPacket()
if ((pkt_time - flow_start) > flow_timeout_) {
    // Save old flow metadata
    std::string old_flow_id = flow.flow_id;

    // Export finished flow
    if (flow.packetCount() > 1) {
        handleFinishedFlow(flow);
    }

    // Create new flow (split)
    BasicFlow new_flow(pkt, old_src_ip, old_dst_ip, old_src_port, old_dst_port);
    new_flow.flow_id = old_flow_id;  // Keep same ID

    // Replace in hash table
    current_flows_[key] = new_flow;
}
```

#### 2. Activity Timeout (Default: 5 seconds)

- **Purpose**: Track active/idle periods within a flow
- **Trigger**: `(current_time - end_active_time) > activity_timeout`
- **Action**: Update active/idle statistics

```cpp
// BasicFlow.cpp: updateActiveIdleTime()
if ((current_time - end_active_time) > threshold) {
    // Record active period
    if ((end_active_time - start_active_time) > 0) {
        flow_active.add(end_active_time - start_active_time);
    }

    // Record idle period
    flow_idle.add(current_time - end_active_time);

    // Start new active period
    start_active_time = current_time;
    end_active_time = current_time;
}
```

### TCP-based Termination

#### RST Flag

```cpp
if (pkt.has_rst) {
    finished = true;  // Immediate termination
}
```

#### FIN Flag (Graceful Close)

```cpp
if (pkt.has_fin) {
    if (is_forward) {
        fwd_fin_flags = 1;
    } else {
        bwd_fin_flags = 1;
    }

    // Both directions sent FIN
    if (fwd_fin_flags + bwd_fin_flags == 2) {
        finished = true;
    }
}
```

### Flow Finalization

```cpp
// FlowGenerator.cpp: finishAllFlows()
// Called at end of capture
for (auto& [key, entry] : current_flows_) {
    if (entry.flow.packetCount() > 1) {
        handleFinishedFlow(entry.flow);
    }
}
```

**Export Order**: Flows are sorted by:

1. Hash bucket (Java-compatible HashMap behavior)
2. Insertion order (stable ordering)

---

## Flow Splitting

Flows are **split** (not closed) when the flow timeout expires. This creates distinct flow records for the same connection.

### Why Split Flows?

1. **Memory Management**: Prevent unbounded flow growth
2. **Analysis Windows**: Enable time-window-based analysis
3. **Stationarity**: Capture changing behavior over time
4. **Dataset Compatibility**: Match CICFlowMeter behavior

### Split Mechanism

```
Original Flow:
┌─────────────────────────────────────────────────┐
│ Flow A: 10.0.0.1:1234 → 10.0.0.2:80            │
│ Start: T=0, Duration: 200s                      │
└─────────────────────────────────────────────────┘

After Timeout (120s):
┌────────────────────────┐  ┌───────────────────┐
│ Flow A (Exported)      │  │ Flow A' (New)     │
│ Start: T=0             │  │ Start: T=125      │
│ Duration: 125s         │  │ Duration: 75s     │
└────────────────────────┘  └───────────────────┘
```

**Key Properties**:

- Same flow_id maintained
- Statistics reset for new flow
- Both flows appear in CSV output
- Packet counts restart from 1

---

## Bidirectional Flow Tracking

### Direction Determination

```cpp
// BasicFlow.cpp: addPacket()
bool is_forward = (src_ip == pkt.src_ip);

if (is_forward) {
    // Forward direction: client → server
    forward_packets++;
    forward_bytes += pkt.payload_bytes;
    fwd_pkt_stats.add(pkt.payload_bytes);
    // ...
} else {
    // Backward direction: server → client
    backward_packets++;
    backward_bytes += pkt.payload_bytes;
    bwd_pkt_stats.add(pkt.payload_bytes);
    // ...
}
```

### Forward Direction

The **first packet** establishes the forward direction:

- Forward source IP/port = flow's src_ip/src_port
- All subsequent packets from this endpoint are "forward"

### Backward Direction

Packets from the opposite endpoint:

- Backward source = flow's destination
- Response packets, ACKs, server data

### Separate Statistics

Each direction maintains:

- Packet count
- Byte count
- Packet length statistics (min, max, mean, std)
- Inter-arrival times (IAT)
- Header byte count
- PSH/URG flag counts
- TCP window size (initial)

---

## Statistical Computation

### Running Statistics Algorithm (Welford's)

Computes mean and variance in a single pass without storing all values:

```cpp
struct RunningStats {
    uint64_t n = 0;        // Count
    double mean = 0.0;     // Running mean
    double m2 = 0.0;       // Sum of squared deviations
    double sum = 0.0;      // Total sum
    double min = 0.0;
    double max = 0.0;

    void add(double v) {
        n++;
        double dev = v - mean;
        mean += dev / n;
        m2 += (n - 1) * dev * (dev / n);
        sum += v;
        min = (n == 1) ? v : std::min(min, v);
        max = (n == 1) ? v : std::max(max, v);
    }

    double variance() const {
        return (n > 1) ? m2 / (n - 1) : 0.0;
    }

    double stddev() const {
        return std::sqrt(variance());
    }
};
```

### Inter-Arrival Time (IAT)

```cpp
// Time between consecutive packets in same direction
if (forward_packets > 0) {
    uint64_t iat = current_timestamp - forward_last_seen;
    forward_iat.add(static_cast<double>(iat));
}
forward_last_seen = current_timestamp;
```

### Subflow Detection

Detects activity bursts separated by > 1 second idle periods:

```cpp
// BasicFlow.cpp: detectUpdateSubflows()
void detectUpdateSubflows(const BasicPacketInfo& pkt) {
    uint64_t ts = packetTimeMicros(pkt);

    if (sf_last_packet_ts == -1) {
        sf_last_packet_ts = ts;
        sf_ac_helper = ts;
        return;
    }

    // Gap > 1 second → new subflow
    if ((ts - sf_last_packet_ts) / 1000000.0 > 1.0) {
        sf_count++;
        updateActiveIdleTime(ts, activity_timeout);
        sf_ac_helper = ts;
    }

    sf_last_packet_ts = ts;
}
```

### Bulk Transfer Detection

Identifies sustained data transfers (4+ consecutive packets with < 1s gaps):

```cpp
// BasicFlow.cpp: updateBackwardBulk()
void updateBackwardBulk(const BasicPacketInfo& pkt) {
    uint64_t size = pkt.payload_bytes;
    if (size == 0) return;

    uint64_t ts = packetTimeMicros(pkt);

    if (bbulk_start_helper == 0) {
        // First packet in potential bulk
        bbulk_start_helper = ts;
        bbulk_packet_count_helper = 1;
        bbulk_size_helper = size;
    } else {
        if ((ts - blast_bulk_ts) / 1000000.0 > 1.0) {
            // Gap too large, reset
            bbulk_start_helper = ts;
            bbulk_packet_count_helper = 1;
            bbulk_size_helper = size;
        } else {
            bbulk_packet_count_helper++;
            bbulk_size_helper += size;

            if (bbulk_packet_count_helper == 4) {
                // Bulk detected
                bbulk_state_count++;
                bbulk_packet_count += 4;
                bbulk_size_total += bbulk_size_helper;
                bbulk_duration += ts - bbulk_start_helper;
            } else if (bbulk_packet_count_helper > 4) {
                // Continue existing bulk
                bbulk_packet_count++;
                bbulk_size_total += size;
                bbulk_duration += ts - blast_bulk_ts;
            }
        }
    }

    blast_bulk_ts = ts;
}
```

**Bulk Metrics**:

- Bulk state count: Number of bulk transfer sequences
- Bulk packet count: Total packets in all bulks
- Bulk size total: Total bytes in all bulks
- Bulk duration: Total time spent in bulk transfers

---

## Data Structures

### BasicPacketInfo

Represents a single decoded packet:

```cpp
struct BasicPacketInfo {
    std::string src_ip, dst_ip;          // IP addresses as strings
    uint8_t src_bytes[16], dst_bytes[16]; // Raw IP bytes
    int addr_len;                         // 4 (IPv4) or 16 (IPv6)
    uint16_t src_port, dst_port;
    uint8_t protocol;
    uint32_t timestamp_sec, timestamp_usec;
    uint32_t payload_bytes;               // L4 payload
    uint32_t header_bytes;                // L2+L3+L4 headers
    bool has_fin, has_syn, has_rst, has_psh, has_ack, has_urg, has_cwr, has_ece;
    int tcp_window;

    std::string fwdFlowId() const;        // src-dst flow ID
    std::string bwdFlowId() const;        // dst-src flow ID
    std::string generateFlowId() const;   // Canonical flow ID
};
```

### BasicFlow

Complete flow statistics:

```cpp
class BasicFlow {
public:
    // Identifiers
    std::string flow_id;
    std::string src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;

    // Timestamps
    uint32_t start_time_sec, start_time_usec;
    uint32_t last_seen_sec, last_seen_usec;
    uint64_t flow_start_time, flow_last_seen;

    // Packet/Byte counts
    int forward_packets, backward_packets;
    uint64_t forward_bytes, backward_bytes;
    uint64_t f_header_bytes, b_header_bytes;

    // TCP flags
    int fin_flag_count, syn_flag_count, rst_flag_count;
    int psh_flag_count, ack_flag_count, urg_flag_count;
    int cwr_flag_count, ece_flag_count;
    int f_psh_cnt, b_psh_cnt;
    int f_urg_cnt, b_urg_cnt;

    // Running statistics
    RunningStats fwd_pkt_stats;      // Forward packet lengths
    RunningStats bwd_pkt_stats;      // Backward packet lengths
    RunningStats flow_iat;            // Flow inter-arrival times
    RunningStats forward_iat;         // Forward IAT
    RunningStats backward_iat;        // Backward IAT
    RunningStats flow_length_stats;   // All packet lengths
    RunningStats flow_active;         // Active period durations
    RunningStats flow_idle;           // Idle period durations

    // Subflow tracking
    uint64_t sf_last_packet_ts;
    int sf_count;

    // Bulk transfer tracking (forward and backward)
    uint64_t fbulk_duration, fbulk_packet_count, fbulk_size_total, fbulk_state_count;
    uint64_t bbulk_duration, bbulk_packet_count, bbulk_size_total, bbulk_state_count;

    // Other
    int init_win_bytes_forward, init_win_bytes_backward;
    uint64_t act_data_pkt_forward;    // Forward packets with payload
    uint64_t min_seg_size_forward;
    bool finished;

    void addPacket(const BasicPacketInfo& pkt);
    // ... 30+ getter methods for computed features
};
```

### FlowGenerator

Manages active flows:

```cpp
class FlowGenerator {
private:
    struct FlowKey {
        array<uint8_t, 16> src, dst;
        uint16_t src_port, dst_port;
        uint8_t protocol, addr_len;
    };

    struct ActiveFlowEntry {
        BasicFlow flow;
        uint64_t insertion_order;  // For deterministic export ordering
    };

    unordered_map<FlowKey, ActiveFlowEntry> current_flows_;
    vector<BasicFlow> finished_flows_;
    function<void(const BasicFlow&)> flow_callback_;

    uint64_t flow_timeout_;              // 120s default
    uint64_t activity_timeout_micros_;   // 5s default

public:
    void addPacket(const BasicPacketInfo& pkt);
    void finishAllFlows();
    void setFlowCallback(function<void(const BasicFlow&)> callback);
};
```

---

## Performance Optimizations

### 1. Hash Table Efficiency

- **Custom Hash**: FNV-1a for deterministic, fast hashing
- **Key Design**: Fixed-size arrays avoid dynamic allocation
- **Reserve Capacity**: Pre-allocate based on expected flow count

### 2. Zero-Copy Processing

- Packet data accessed directly from libpcap buffer
- No intermediate copies for header parsing
- String IP addresses cached per flow

### 3. Streaming Architecture

- Flows exported immediately upon completion
- Bounded memory usage regardless of capture duration
- CSV written incrementally, no buffering

### 4. Welford's Algorithm

- Single-pass statistics computation
- No storage of individual packet values
- O(1) per-packet complexity for mean/variance

### 5. Compiler Optimizations

```cmake
-O3                  # Maximum optimization
-march=native        # CPU-specific instructions
-flto                # Link-time optimization
-DNDEBUG             # Disable assertions
```

### 6. Bulk Detection Optimization

- Uses object identity comparison (Java compatibility)
- Always processes backward bulk to avoid byte array comparison
- Tracks helper variables to minimize recomputation

---

## Thread Safety

**Current Design**: Single-threaded

- PacketReader → FlowGenerator → CSVWriter runs in one thread
- No mutex/lock overhead
- Suitable for live capture (I/O bound) and offline processing

**Future Enhancement**: Multi-threaded packet processing with per-thread flow tables

---

## Compatibility

### CICFlowMeter Compatibility

TriFlowMeter maintains compatibility with CICFlowMeter output:

1. **Same 84 CSV columns** in identical order
2. **Java-compatible flow ID hashing** for deterministic export order
3. **Identical feature computation** (including quirks like bulk detection)
4. **Same default timeouts** (120s flow, 5s activity)

### Deviations from CICFlowMeter

1. **Performance**: 10-100x faster due to C++ implementation
2. **Memory**: More efficient with streaming architecture
3. **Bugs Fixed**: Corrected several statistical computation errors
4. **Platform Support**: Native Windows/Linux/macOS builds

---

## Error Handling

### Packet Discarding

Packets are discarded if:

- Cannot parse Ethernet/IP/Transport headers
- Unsupported protocol (not TCP/UDP)
- Malformed headers (length mismatches)

Discarded packets increment `stats.discarded` but don't affect flows.

### Flow Validation

Flows with `packetCount() <= 1` are not exported (insufficient data for statistics).

### Timeout Edge Cases

If packet timestamps go backwards (non-monotonic), flows may be created with negative durations. In practice, libpcap guarantees monotonic timestamps.

---

## Future Enhancements

1. **ICMP Support**: Add ICMP flow tracking
2. **IPv6 Flow Labels**: Utilize IPv6 flow label field
3. **Application Layer**: Deep packet inspection for protocols (HTTP, DNS, TLS)
4. **Machine Learning**: Embedded classification models
5. **Distributed Processing**: Cluster-based high-speed analysis
6. **Database Export**: Direct output to ClickHouse, PostgreSQL, etc.

---

## References

- **Welford's Algorithm**: Donald Knuth, _The Art of Computer Programming_, Vol 2
- **FNV Hash**: [http://www.isthe.com/chongo/tech/comp/fnv/](http://www.isthe.com/chongo/tech/comp/fnv/)
- **CICFlowMeter**: Canadian Institute for Cybersecurity
- **libpcap**: [https://www.tcpdump.org/](https://www.tcpdump.org/)

---

_This architecture document is maintained under GPL-3.0 license._
