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
2. [Source File Map](#source-file-map)
3. [Packet Processing Pipeline](#packet-processing-pipeline)
4. [Flow Lifecycle](#flow-lifecycle)
5. [Flow Creation](#flow-creation)
6. [Packet Assignment to Flows](#packet-assignment-to-flows)
7. [Flow Timeout and Termination](#flow-timeout-and-termination)
8. [Flow Splitting](#flow-splitting)
9. [Bidirectional Flow Tracking](#bidirectional-flow-tracking)
10. [Statistical Computation](#statistical-computation)
11. [Data Structures](#data-structures)
12. [CSV Export](#csv-export)
13. [Live Dashboard](#live-dashboard)
14. [Execution Modes](#execution-modes)
15. [Performance Optimizations](#performance-optimizations)
16. [Thread Safety](#thread-safety)
17. [Error Handling](#error-handling)
18. [Platform Support](#platform-support)

---

## System Overview

TriFlowMeter follows a pipeline architecture with seven components:

```
┌──────────────┐    ┌──────────────┐    ┌───────────────┐    ┌──────────────┐
│   Packet     │───▶│   Packet     │───▶│     Flow      │───▶│  CSV Writer  │
│   Reader     │    │   Decoders   │    │   Generator   │    │              │
└──────────────┘    └──────────────┘    └───────────────┘    └──────────────┘
       │                                        │                    │
       ▼                                        ▼                    ▼
┌──────────────┐                        ┌───────────────┐    ┌──────────────┐
│  CLI Options │                        │  Basic Flow   │    │     Live     │
│              │                        │  (per-flow    │    │  Dashboard   │
│              │                        │   statistics) │    │              │
└──────────────┘                        └───────────────┘    └──────────────┘
                                                                     │
                                                              ┌──────────────┐
                                                              │  File Utils  │
                                                              └──────────────┘
```

### Core Components

| Component | Files | Responsibility |
|-----------|-------|----------------|
| **CLIOptions** | `CLIOptions.h/cpp` | Parses command-line arguments, resolves output paths |
| **PacketReader** | `PacketReader.h/cpp` | Captures packets via libpcap (offline or live) |
| **PacketDecoders** | `PacketDecoders.h/cpp` | Decodes Ethernet/IPv4/IPv6/TCP/UDP/L2TP headers |
| **FlowGenerator** | `FlowGenerator.h/cpp` | Aggregates packets into bidirectional flows |
| **BasicFlow** | `BasicFlow.h/cpp` | Represents a single flow with all statistical features |
| **CSVWriter** | `CSVWriter.h/cpp` | Serializes 81-column flow records to CSV |
| **LiveDashboard** | `LiveDashboard.h/cpp` | Real-time terminal UI showing capture progress |
| **JavaNumberFormat** | `JavaNumberFormat.h/cpp` | Java-compatible double formatting for CSV output |
| **FileUtils** | `FileUtils.h/cpp` | Fixes file ownership when running under sudo |
| **BasicPacketInfo** | `BasicPacketInfo.h` | POD struct representing a decoded packet |

---

## Source File Map

```
TriFlowMeter/
├── CMakeLists.txt              # Build system (CMake 3.16+, C++17)
├── include/
│   ├── BasicFlow.h             # Flow class + RunningStats struct
│   ├── BasicPacketInfo.h       # Packet struct + PacketStats struct
│   ├── CLIOptions.h            # CLI structs (CLIOptions, CLIParseResult)
│   ├── CSVWriter.h             # Static CSV output methods
│   ├── FileUtils.h             # fixOwnershipIfSudo()
│   ├── FlowGenerator.h         # FlowKey, FlowKeyHash, ActiveFlowEntry
│   ├── JavaNumberFormat.h      # javafmt::formatJavaLikeDouble()
│   ├── LiveDashboard.h         # Terminal dashboard class
│   ├── PacketDecoders.h        # decodeIPv4/IPv6/L2TP declarations
│   └── PacketReader.h          # libpcap wrapper (Offline/Live modes)
└── src/
    ├── main.cpp                # Entry point, mode dispatch, signal handling
    ├── BasicFlow.cpp           # Flow statistics, flag checking, active/idle tracking
    ├── CLIOptions.cpp          # Argument parsing, path resolution
    ├── CSVWriter.cpp           # 81-column CSV header + row serialization
    ├── FileUtils.cpp           # chown/chmod under sudo
    ├── FlowGenerator.cpp       # Flow table, lookup, timeout, finalization
    ├── JavaNumberFormat.cpp    # Scientific ↔ plain notation conversion
    ├── LiveDashboard.cpp       # ANSI terminal rendering
    ├── PacketDecoders.cpp      # IPv4/IPv6/L2TP/TCP/UDP parsing
    └── PacketReader.cpp        # libpcap open/read loop
```

---

## Packet Processing Pipeline

Each packet undergoes the following stages:

### 1. Packet Capture (`PacketReader`)

- **Offline**: `pcap_open_offline()` reads PCAP files
- **Live**: `pcap_open_live()` captures from a network interface (Ethernet/DLT_EN10MB only)
- **Output**: Raw packet bytes + pcap timestamp (`tv_sec`, `tv_usec`)

### 2. Link-Layer Parsing (`PacketReader::readAll`)

```
Ethernet Frame
    └─▶ EtherType check:
         ├─ 0x0800 (IPv4) → decodeIPv4()
         ├─ 0x86DD (IPv6) → decodeIPv6()
         └─ fallback     → decodeL2TP() for VPN/tunnel detection
```

**Note**: ARP decoding (`decodeArpCompat`) is declared but **disabled** in the current version. ARP packets are counted as discarded.

### 3. Network/Transport Decoding (`PacketDecoders`)

**Extracted into `BasicPacketInfo`**:

| Field | Source |
|-------|--------|
| `src_ip`, `dst_ip` | IPv4/IPv6 header (string + raw bytes) |
| `src_port`, `dst_port` | TCP/UDP header |
| `protocol` | `6` (TCP) or `17` (UDP) |
| `timestamp_sec`, `timestamp_usec` | pcap header |
| `payload_bytes` | IP total length − IP header − transport header |
| `header_bytes` | TCP data offset × 4 or 8 (UDP) |
| `tcp_window` | TCP window field |
| `ip_ttl` | IPv4 TTL or IPv6 Hop Limit |
| TCP flags | `has_fin`, `has_syn`, `has_rst`, `has_psh`, `has_ack`, `has_urg`, `has_cwr`, `has_ece` |

#### L2TP / VPN Decapsulation

When a packet's outer IP protocol is L2TP (protocol 115), the decoder:
1. Skips the outer IP header and 6-byte L2TP header
2. Checks the inner packet's IP version (4 or 6)
3. Recursively decodes the inner packet via `decodeIPv4()` or `decodeIPv6()`
4. Increments `PacketStats::vpn_packets`

### 4. Flow Assignment (`FlowGenerator::addPacket`)

The packet is matched to an existing flow or creates a new one (see [Packet Assignment to Flows](#packet-assignment-to-flows)).

### 5. Feature Computation (`BasicFlow::addPacket`)

Real-time statistical updates using `RunningStats`:

- Packet length statistics (fwd, bwd, total)
- Inter-arrival times (fwd, bwd, flow)
- TCP flag counters
- Active/idle period tracking

### 6. Export (`CSVWriter` / `flow_callback_`)

Finished flows are immediately serialized and written via the registered callback.

---

## Flow Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Created   │────▶│   Active    │────▶│  Finishing   │────▶│  Exported   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
      │                    │                    │
      │                    │                    │
      └────────────────────┴────────────────────┘
                   (Timeout / RST)
```

### States

1. **Created**: Flow is instantiated when the first packet of a new 5-tuple arrives
2. **Active**: Flow receives and processes subsequent packets
3. **Finishing**: Flow is marked as `finished = true` (FIN+FIN or RST or flow timeout)
4. **Exported**: Flow statistics are written to CSV and removed from the flow table

---

## Flow Creation

### When Flows are Created

1. **First packet from a new 5-tuple** — no matching forward or backward key exists
2. **Flow timeout expires** — the old flow is exported and a new flow begins for the same 5-tuple

### Flow Initialization

The constructor `BasicFlow(pkt, activity_timeout_micros)`:

- Assigns the flow ID from `pkt.fwdFlowId()`
- Records `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`
- Initializes all timestamps from the first packet
- Processes the first packet as a forward packet:
  - Sets `fwd_initial_ttl`, `init_win_bytes_forward`, `min_seg_size_forward`
  - Adds payload bytes to `fwd_pkt_stats` and `flow_length_stats`
  - Increments `forward_packets`, `forward_bytes`
- Checks for RST (immediate finish) or FIN (sets `fwd_fin_flags`)

A second constructor `BasicFlow(pkt, old_src_ip, old_dst_ip, old_src_port, old_dst_port, ...)` exists for flow splits, preserving the original source/destination orientation.

---

## Packet Assignment to Flows

### Flow Key

```cpp
struct FlowKey {
    array<uint8_t, 16> src;   // Raw IP bytes (4 for IPv4, 16 for IPv6)
    array<uint8_t, 16> dst;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t addr_len;         // 4 or 16
};
```

### Lookup Process

```
1. Generate forward flow key from packet
2. Search hash table for forward key
3. If not found:
   a. Generate backward flow key (src ↔ dst swapped)
   b. Search hash table for backward key
4. If found (forward or backward):
   a. Compute elapsed time since flow start
   b. If timeout exceeded → export current flow, create new flow (split)
   c. Else → call flow.addPacket(pkt), check if finished
5. If not found:
   a. Create new BasicFlow from packet
   b. Insert into hash table with forward key
```

### Hash Function

FNV-1a hash over all `FlowKey` fields for deterministic, fast hashing.

---

## Flow Timeout and Termination

### Flow Timeout (Default: 120 seconds)

- **Purpose**: Split long-lived flows into bounded segments
- **Trigger**: `(packet_time - flow_start_time) > flow_timeout`
- **Action**:
  1. Export the current flow (if `packetCount() > 0`)
  2. Create a new flow with the same 5-tuple and preserved flow ID
  3. Replace the entry in the hash table

### Activity Timeout (Default: 5 seconds)

- **Purpose**: Track active/idle periods within a flow
- **Trigger**: `(current_time - end_active_time) > activity_timeout`
- **Action**: Record the ending active period duration, record the idle period duration, start a new active period

```cpp
// BasicFlow.cpp: updateActiveIdleTime()
if ((current_time - end_active_time) > threshold) {
    if ((end_active_time - start_active_time) > 0) {
        flow_active.add(end_active_time - start_active_time);
    }
    flow_idle.add(current_time - end_active_time);
    start_active_time = current_time;
    end_active_time = current_time;
} else {
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
    if (is_forward)  fwd_fin_flags = 1;
    else             bwd_fin_flags = 1;

    if (fwd_fin_flags + bwd_fin_flags == 2) {
        finished = true;  // Both directions sent FIN
    }
}
```

### Flow Finalization (`finishAllFlows`)

Called at the end of capture to export all remaining active flows:

- Flows with `packetCount() <= 1` are skipped (insufficient data for statistics)
- Remaining flows are sorted by Java-compatible HashMap bucket order and insertion order for deterministic output
- Uses `javaStringHash()` and `javaSpreadHash()` to compute bucket indices against a capacity derived from `peak_current_flows_`

---

## Flow Splitting

Flows are **split** (not closed) when the flow timeout expires. This creates distinct flow records for the same connection.

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

- Same `flow_id` maintained across splits
- Statistics reset for the new flow
- Both flow segments appear in CSV output
- Source/destination orientation is preserved from the original flow

---

## Bidirectional Flow Tracking

### Direction Determination

```cpp
bool is_forward = (src_ip == pkt.src_ip);
```

The **first packet** establishes the forward direction. All subsequent packets from the same source IP are "forward"; packets from the opposite endpoint are "backward".

### Separate Statistics per Direction

| Tracked per direction | Forward | Backward |
|----------------------|---------|----------|
| Packet count | `forward_packets` | `backward_packets` |
| Byte count (payload) | `forward_bytes` | `backward_bytes` |
| Header byte count | `f_header_bytes` | `b_header_bytes` |
| Packet length stats | `fwd_pkt_stats` | `bwd_pkt_stats` |
| Inter-arrival times | `forward_iat` | `backward_iat` |
| Active data packets | `act_data_pkt_forward` | `act_data_pkt_backward` |
| Initial TCP window | `init_win_bytes_forward` | `init_win_bytes_backward` |
| Initial TTL | `fwd_initial_ttl` | `bwd_initial_ttl` |
| FIN tracking | `fwd_fin_flags` | `bwd_fin_flags` |

---

## Statistical Computation

### Running Statistics (Welford's Algorithm)

Computes mean and standard deviation in a single pass without storing individual values:

```cpp
struct RunningStats {
    uint64_t n = 0;
    double mean = 0.0;
    double m2 = 0.0;       // Sum of squared deviations
    double sum = 0.0;
    double min = 0.0;
    double max = 0.0;

    void add(double v) {
        if (n == 0) { min = v; max = v; }
        n++;
        double dev = v - mean;
        mean += dev / n;
        m2 += (n - 1.0) * dev * (dev / n);
        sum += v;
        if (v < min) min = v;
        if (v > max) max = v;
    }

    double stddev() const {
        if (n <= 1) return 0.0;
        const double var = m2 / (n - 1);
        return var > 0.0 ? sqrt(var) : 0.0;
    }
};
```

Used for: `fwd_pkt_stats`, `bwd_pkt_stats`, `flow_length_stats`, `forward_iat`, `backward_iat`, `flow_iat`, `flow_active`, `flow_idle`.

### Inter-Arrival Time (IAT)

```cpp
// Forward IAT: only recorded when forward_packets > 0
if (forward_packets > 0) {
    forward_iat.add(current_timestamp - forward_last_seen);
}
forward_last_seen = current_timestamp;
```

Same logic applies for backward IAT and flow-level IAT.

---

## Data Structures

### BasicPacketInfo

Represents a single decoded packet:

```cpp
struct BasicPacketInfo {
    std::string src_ip, dst_ip;
    uint8_t src_bytes[16], dst_bytes[16];   // Raw IP bytes for key generation
    int addr_len;                            // 4 (IPv4) or 16 (IPv6)
    uint16_t src_port, dst_port;
    uint8_t protocol;
    uint32_t timestamp_sec, timestamp_usec;
    uint32_t payload_bytes;                  // Transport payload
    uint32_t header_bytes;                   // Transport header size
    bool has_fin, has_syn, has_rst, has_psh, has_ack, has_urg, has_cwr, has_ece;
    int tcp_window;
    uint8_t ip_ttl;

    std::string generateFlowId() const;     // Canonical (sorted) flow ID
    std::string fwdFlowId() const;           // src→dst flow ID
    std::string bwdFlowId() const;           // dst→src flow ID
};
```

### PacketStats

```cpp
struct PacketStats {
    long long total = 0;
    long long valid = 0;
    long long discarded = 0;
    long long vpn_packets = 0;
};
```

### FlowGenerator Internals

```cpp
class FlowGenerator {
    unordered_map<FlowKey, ActiveFlowEntry, FlowKeyHash> current_flows_;
    vector<BasicFlow> finished_flows_;             // Optional storage
    function<void(const BasicFlow&)> flow_callback_;
    bool store_finished_flows_;
    int finished_flow_count_;
    uint64_t flow_timeout_;                        // Microseconds
    uint64_t activity_timeout_micros_;             // Microseconds
    uint64_t next_insertion_order_;                 // Monotonic counter
    size_t peak_current_flows_;                     // For finalization ordering
};
```

---

## CSV Export

### Header

The CSV header is written by `CSVWriter::writeHeader()` as a fixed 81-column string. See [FEATURES.md](FEATURES.md) for the complete column listing.

### Row Serialization

`CSVWriter::writeFlowRow()` serializes a `BasicFlow` into a single CSV row:

- Flows with `packetCount() <= 0` are silently skipped (returns `false`)
- Integer fields are written directly
- Floating-point fields use `javafmt::formatJavaLikeDouble()` for Java-compatible formatting:
  - Values in `[1e-3, 1e7)` are written in plain notation (e.g., `1234.5`)
  - Values outside this range use scientific notation with Java-style exponents (e.g., `1.5E8`)
  - Whole-number doubles include `.0` suffix (e.g., `42.0`)
  - NaN → `"NaN"`, ±Infinity → `"Infinity"` / `"-Infinity"`

### Export-Time Computed Features

Three ratio features are computed at export time in `writeFlowRow()` rather than tracked incrementally:

1. **Payload Ratio** = `backward_bytes / forward_bytes`
2. **Packet Count Ratio** = `backward_packets / forward_packets`
3. **Header-to-Total Ratio** = `total_header_bytes / (total_bytes + total_header_bytes)`

---

## Live Dashboard

`LiveDashboard` provides a real-time terminal UI using ANSI escape codes:

### Layout

```
+--------------------------------------------------------------------------------+
| Source: eth0           | Uptime: 00:05:32       | Packets: 1.2M                |
+------------------------+------------------------+------------------------------+
| Valid: 1.1M            | Discarded: 45.2K       | Written Flows: 8.5K         |
+------------------------+-------------------------------------------------------+
| Active Flows: 342      | CSV Output: /path/to/output_flows.csv                 |
+--------------------------------------------------------------------------------+
```

### Features

- ASCII art banner displayed on first render (TriFlowMeter logo)
- 250ms refresh throttle (via `forceRefresh()` / `refreshIfDue()`)
- In-place terminal updates using cursor movement escape codes (`\033[nA`, `\033[2K`)
- Human-readable count formatting: K (thousands), M (millions), G (billions)
- Tracks: total/valid/discarded packets, VPN packets, written flows, active flows, uptime

---

## Execution Modes

`main.cpp` dispatches into three execution modes based on CLI flags:

### 1. Stdout Mode (`--stdout`)

- Writes CSV header + rows to `stdout`
- Progress messages go to `stderr`
- No dashboard, no file output
- Flows are not stored in memory (`setStoreFinishedFlows(false)`)
- Ideal for piping into downstream tools

### 2. Live Capture (`--live <interface>`)

- Requires root/admin privileges
- Opens live pcap handle with `pcap_open_live()`
- Registers signal handlers for `SIGINT`/`SIGTERM` to gracefully stop capture
- Displays LiveDashboard on terminal
- Streams flows to CSV file as they finish
- 250ms UI tick for dashboard updates

### 3. Offline Mode (default)

- Reads a PCAP file
- Displays LiveDashboard with progress
- Streams flows to CSV file
- On completion: final statistics printed

### Signal Handling

- `SIGINT` and `SIGTERM` set a `volatile sig_atomic_t g_stop_capture` flag
- The packet read loop checks this flag between packets
- Allows graceful shutdown during live capture

### Output Path Resolution (`resolveCsvPath`)

| Scenario | Output |
|----------|--------|
| No output specified (offline) | `{pcap_stem}_Flow.csv` (legacy naming) |
| No output specified (live) | `{interface}_flows.csv` |
| Output is directory or has no extension | `{directory}/{stem}_flows.csv` |
| Output is a file path | Used as-is |

All output directories are created automatically. File ownership is restored to `SUDO_UID`/`SUDO_GID` when running under sudo.

---

## Performance Optimizations

### 1. Hash Table Efficiency

- **Custom FNV-1a hash**: Deterministic, fast hashing over fixed-size `FlowKey` arrays
- **Fixed-size keys**: No dynamic allocation in hot path
- **Binary IP comparison**: Uses raw bytes, not string comparison

### 2. Zero-Copy Packet Parsing

- Packet data accessed directly from libpcap buffer via `reinterpret_cast`
- No intermediate buffer copies for header parsing
- String IP addresses created once per flow, not per packet

### 3. Streaming Architecture

- Flows exported immediately upon completion via callback
- `store_finished_flows_` can be disabled to prevent memory accumulation
- Bounded memory usage regardless of capture duration

### 4. Welford's Algorithm

- Single-pass statistics computation (mean, stddev) — no per-packet storage
- No storage of individual packet values
- O(1) per-packet complexity for statistical updates

### 5. Compiler Optimizations

```cmake
-O3                  # Maximum optimization
-march=native        # CPU-specific instructions (optional, enabled by default)
-flto                # Link-time optimization (Release builds)
-DNDEBUG             # Disable assertions
```

Controlled by `TRIFLOWMETER_ENABLE_NATIVE_OPT` CMake option.

---

## Thread Safety

**Current Design**: Single-threaded

- `PacketReader → FlowGenerator → CSVWriter` runs on the main thread
- No mutex/lock overhead
- Live dashboard rendering happens synchronously within the packet loop callbacks

---

## Error Handling

### Packet Discarding

Packets are discarded if:

- Ethernet frame is too short for an Ethernet header
- IP header cannot be parsed (insufficient bytes)
- Transport protocol is not TCP or UDP (and not L2TP-encapsulated)
- L2TP decapsulation fails

Discarded packets increment `PacketStats::discarded` but do not affect flows.

### Flow Export Validation

- `writeFlowRow()` silently skips flows with `packetCount() <= 0`
- `finishAllFlows()` skips flows with `packetCount() <= 1`

### Live Capture Constraints

- Only Ethernet interfaces (`DLT_EN10MB`) are supported for live capture
- Non-Ethernet interfaces cause an immediate error on `open()`

---

## Platform Support

### Build System

- **CMake 3.16+** with C++17 (`CMAKE_CXX_STANDARD 17`)
- **Compilers**: GCC 7+, Clang 6+, MSVC 2017+
- **Dependency**: libpcap (Linux/macOS) or Npcap/WinPcap (Windows)

### Platform-Specific Code

| Component | Linux/macOS | Windows |
|-----------|-------------|---------|
| Network headers | `<netinet/ip.h>`, `<netinet/tcp.h>`, etc. | Custom struct definitions |
| Ethernet header | `<netinet/if_ether.h>` | Custom `ether_header` struct |
| Pcap library | `libpcap` | `wpcap` + `Packet` + `ws2_32` |
| File ownership | `chown()` via SUDO_UID/GID | Not applicable |

---

## References

- **Welford's Algorithm**: Donald Knuth, _The Art of Computer Programming_, Vol 2
- **FNV-1a Hash**: [http://www.isthe.com/chongo/tech/comp/fnv/](http://www.isthe.com/chongo/tech/comp/fnv/)
- **CICFlowMeter**: Canadian Institute for Cybersecurity
- **libpcap**: [https://www.tcpdump.org/](https://www.tcpdump.org/)

---

_This architecture document is maintained under GPL-3.0 license._
