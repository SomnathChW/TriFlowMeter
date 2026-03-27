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

# TriFlowMeter Feature Descriptions

This document provides detailed descriptions of all 84 features extracted by TriFlowMeter for each network flow.

## Feature Categories

1. [Flow Identifiers](#flow-identifiers) (6 features)
2. [Temporal Features](#temporal-features) (2 features)
3. [Packet Statistics](#packet-statistics) (12 features)
4. [Inter-Arrival Time (IAT) Features](#inter-arrival-time-iat-features) (16 features)
5. [TCP Flag Features](#tcp-flag-features) (14 features)
6. [Flow Rate Features](#flow-rate-features) (4 features)
7. [Length Statistics](#length-statistics) (13 features)
8. [Bulk Transfer Features](#bulk-transfer-features) (6 features)
9. [Subflow Features](#subflow-features) (4 features)
10. [TCP-Specific Features](#tcp-specific-features) (4 features)
11. [Active/Idle Time Features](#activeidle-time-features) (8 features)
12. [Label](#label) (1 feature)

---

## Flow Identifiers

### 1. Flow ID

- **Type**: String
- **Format**: `{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}`
- **Description**: Unique identifier for the flow in forward direction
- **Example**: `192.168.1.10-8.8.8.8-52341-53-17`
- **Use**: Primary key for flow identification

### 2. Src IP

- **Type**: String (IPv4 or IPv6)
- **Description**: Source IP address (originator of the flow)
- **Example**: `192.168.1.10` or `2001:db8::1`
- **Use**: Network endpoint identification

### 3. Src Port

- **Type**: Integer (0-65535)
- **Description**: Source port number
- **Example**: `52341`
- **Use**: Application/service identification, ephemeral port analysis

### 4. Dst IP

- **Type**: String (IPv4 or IPv6)
- **Description**: Destination IP address
- **Example**: `8.8.8.8`
- **Use**: Network endpoint identification

### 5. Dst Port

- **Type**: Integer (0-65535)
- **Description**: Destination port number
- **Example**: `80` (HTTP), `443` (HTTPS), `53` (DNS)
- **Use**: Service identification, application classification

### 6. Protocol

- **Type**: Integer
- **Values**: `6` (TCP), `17` (UDP)
- **Description**: IP protocol number
- **Use**: Transport layer protocol identification

---

## Temporal Features

### 7. Timestamp

- **Type**: String
- **Format**: `DD/MM/YYYY HH:MM:SS AM/PM`
- **Description**: Human-readable timestamp of first packet in flow
- **Example**: `27/03/2026 08:45:32 PM`
- **Use**: Temporal analysis, time-of-day patterns

### 8. Flow Duration

- **Type**: Integer (microseconds)
- **Description**: Total duration from first to last packet
- **Formula**: `last_seen_time - flow_start_time`
- **Example**: `125483920` (125.48 seconds)
- **Use**: Session length analysis, long-lived connection detection

---

## Packet Statistics

### 9. Total Fwd Packet

- **Type**: Integer
- **Description**: Number of packets in forward direction (src → dst)
- **Range**: 1 to flow size
- **Use**: Traffic asymmetry analysis, download/upload ratio

### 10. Total Bwd packets

- **Type**: Integer
- **Description**: Number of packets in backward direction (dst → src)
- **Range**: 0 to flow size
- **Use**: Interactive vs. unidirectional flow detection

### 11. Total Length of Fwd Packet

- **Type**: Float (bytes)
- **Description**: Sum of payload bytes in forward direction
- **Formula**: `sum(fwd_packet_payloads)`
- **Use**: Data volume analysis

### 12. Total Length of Bwd Packet

- **Type**: Float (bytes)
- **Description**: Sum of payload bytes in backward direction
- **Formula**: `sum(bwd_packet_payloads)`
- **Use**: Response size analysis

### 13-16. Fwd Packet Length {Max, Min, Mean, Std}

- **Type**: Float (bytes)
- **Description**: Statistical measures of forward packet payload sizes
- **Use**:
    - **Max**: Large packet detection (e.g., full MTU)
    - **Min**: Small packet detection (e.g., ACKs, keep-alives)
    - **Mean**: Average packet size
    - **Std**: Packet size variability

### 17-20. Bwd Packet Length {Max, Min, Mean, Std}

- **Type**: Float (bytes)
- **Description**: Statistical measures of backward packet payload sizes
- **Use**: Server response characterization, traffic pattern analysis

---

## Inter-Arrival Time (IAT) Features

Inter-Arrival Time measures the time gap between consecutive packets.

### 21-25. Flow IAT {Mean, Std, Max, Min}

- **Type**: Float (microseconds)
- **Description**: IAT statistics across all packets in flow
- **Formula**: `IAT[i] = timestamp[i] - timestamp[i-1]`
- **Use**:
    - **Mean**: Average packet rate
    - **Std**: Traffic burstiness
    - **Max**: Longest gap (idle period)
    - **Min**: Shortest gap (rapid-fire packets)

### 26-30. Fwd IAT {Total, Mean, Std, Max, Min}

- **Type**: Float (microseconds)
- **Description**: IAT statistics for forward direction packets only
- **Use**: Client sending behavior, upload pattern analysis
- **Note**: Only computed if forward_packets > 1

### 31-35. Bwd IAT {Total, Mean, Std, Max, Min}

- **Type**: Float (microseconds)
- **Description**: IAT statistics for backward direction packets only
- **Use**: Server response timing, download pattern analysis
- **Note**: Only computed if backward_packets > 1

---

## TCP Flag Features

TCP flags indicate control information in TCP protocol.

### 36. Fwd PSH Flags

- **Type**: Integer
- **Description**: Count of PSH flags in forward direction
- **TCP Flag**: Push (urgent data delivery)
- **Use**: Interactive application detection (SSH, Telnet)

### 37. Bwd PSH Flags

- **Type**: Integer
- **Description**: Count of PSH flags in backward direction
- **Use**: Server push behavior

### 38. Fwd URG Flags

- **Type**: Integer
- **Description**: Count of URG flags in forward direction
- **TCP Flag**: Urgent (out-of-band data)
- **Use**: Urgent data detection (rare in modern networks)

### 39. Bwd URG Flags

- **Type**: Integer
- **Description**: Count of URG flags in backward direction
- **Use**: Urgent response detection

### 40. Fwd Header Length

- **Type**: Integer (bytes)
- **Description**: Total header bytes in forward direction
- **Formula**: `sum(ethernet + IP + TCP/UDP headers)`
- **Use**: Protocol overhead analysis

### 41. Bwd Header Length

- **Type**: Integer (bytes)
- **Description**: Total header bytes in backward direction
- **Use**: Protocol overhead analysis

### 42-49. {FIN, SYN, RST, PSH, ACK, URG, CWR, ECE} Flag Count

- **Type**: Integer
- **Description**: Total count of each TCP flag in both directions
- **Flags**:
    - **FIN**: Connection termination
    - **SYN**: Connection establishment
    - **RST**: Connection reset
    - **PSH**: Push data immediately
    - **ACK**: Acknowledgment
    - **URG**: Urgent pointer valid
    - **CWR**: Congestion Window Reduced (ECN)
    - **ECE**: ECN Echo (ECN)
- **Use**:
    - SYN/FIN ratio: Connection behavior
    - RST count: Aborted connections
    - ACK count: Protocol conformance
    - CWR/ECE: Congestion detection

---

## Flow Rate Features

### 50. Flow Bytes/s

- **Type**: Float (bytes/second)
- **Description**: Total bytes per second
- **Formula**: `(forward_bytes + backward_bytes) / (duration_seconds)`
- **Use**: Bandwidth utilization, throughput analysis

### 51. Flow Packets/s

- **Type**: Float (packets/second)
- **Description**: Total packets per second
- **Formula**: `(forward_packets + backward_packets) / (duration_seconds)`
- **Use**: Packet rate analysis, DoS detection

### 52. Fwd Packets/s

- **Type**: Float (packets/second)
- **Description**: Forward packets per second
- **Formula**: `forward_packets / (duration_seconds)`
- **Use**: Upload rate analysis

### 53. Bwd Packets/s

- **Type**: Float (packets/second)
- **Description**: Backward packets per second
- **Formula**: `backward_packets / (duration_seconds)`
- **Use**: Download rate analysis

---

## Length Statistics

### 54. Packet Length Min

- **Type**: Float (bytes)
- **Description**: Minimum packet payload size across all packets
- **Use**: Small packet detection

### 55. Packet Length Max

- **Type**: Float (bytes)
- **Description**: Maximum packet payload size across all packets
- **Use**: MTU analysis, large packet detection

### 56. Packet Length Mean

- **Type**: Float (bytes)
- **Description**: Average packet payload size
- **Formula**: `sum(all_packet_payloads) / total_packets`
- **Use**: Flow characterization

### 57. Packet Length Std

- **Type**: Float (bytes)
- **Description**: Standard deviation of packet payload sizes
- **Use**: Packet size variability, traffic regularity

### 58. Packet Length Variance

- **Type**: Float (bytes²)
- **Description**: Variance of packet payload sizes
- **Formula**: `std²`
- **Use**: Statistical analysis, outlier detection

### 59. Down/Up Ratio

- **Type**: Float
- **Description**: Ratio of backward to forward packets
- **Formula**: `backward_packets / forward_packets`
- **Use**:
    - `> 1`: Download-heavy (e.g., video streaming)
    - `< 1`: Upload-heavy (e.g., backup, P2P seeding)
    - `≈ 1`: Balanced (e.g., VoIP, gaming)

### 60. Average Packet Size

- **Type**: Float (bytes)
- **Description**: Average payload size across all packets
- **Formula**: `flow_length_stats.sum / packet_count`
- **Use**: Flow characterization

### 61. Fwd Segment Size Avg

- **Type**: Float (bytes)
- **Description**: Average forward packet payload size
- **Formula**: `fwd_pkt_stats.sum / forward_packets`
- **Use**: Upload segment size analysis

### 62. Bwd Segment Size Avg

- **Type**: Float (bytes)
- **Description**: Average backward packet payload size
- **Formula**: `bwd_pkt_stats.sum / backward_packets`
- **Use**: Download segment size analysis

---

## Bulk Transfer Features

Bulk transfers are detected as 4+ consecutive packets with < 1 second gaps.

### 63. Fwd Bytes/Bulk Avg

- **Type**: Integer (bytes)
- **Description**: Average bytes per bulk transfer in forward direction
- **Formula**: `fbulk_size_total / fbulk_state_count`
- **Use**: Sustained upload detection

### 64. Fwd Packet/Bulk Avg

- **Type**: Integer
- **Description**: Average packets per bulk transfer in forward direction
- **Formula**: `fbulk_packet_count / fbulk_state_count`
- **Use**: Upload burst size

### 65. Fwd Bulk Rate Avg

- **Type**: Integer (bytes/second)
- **Description**: Average bulk transfer rate in forward direction
- **Formula**: `fbulk_size_total / (fbulk_duration_seconds)`
- **Use**: Upload throughput during bursts

### 66. Bwd Bytes/Bulk Avg

- **Type**: Integer (bytes)
- **Description**: Average bytes per bulk transfer in backward direction
- **Use**: Sustained download detection

### 67. Bwd Packet/Bulk Avg

- **Type**: Integer
- **Description**: Average packets per bulk transfer in backward direction
- **Use**: Download burst size

### 68. Bwd Bulk Rate Avg

- **Type**: Integer (bytes/second)
- **Description**: Average bulk transfer rate in backward direction
- **Use**: Download throughput during bursts
- **Example Use Case**: Video streaming, file download

---

## Subflow Features

Subflows are activity bursts separated by > 1 second idle periods.

### 69. Subflow Fwd Packets

- **Type**: Integer
- **Description**: Average forward packets per subflow
- **Formula**: `forward_packets / subflow_count`
- **Use**: Activity burst analysis

### 70. Subflow Fwd Bytes

- **Type**: Integer (bytes)
- **Description**: Average forward bytes per subflow
- **Formula**: `forward_bytes / subflow_count`
- **Use**: Upload burst size

### 71. Subflow Bwd Packets

- **Type**: Integer
- **Description**: Average backward packets per subflow
- **Formula**: `backward_packets / subflow_count`
- **Use**: Response burst analysis

### 72. Subflow Bwd Bytes

- **Type**: Integer (bytes)
- **Description**: Average backward bytes per subflow
- **Formula**: `backward_bytes / subflow_count`
- **Use**: Download burst size

**Note**: All subflow features are 0 if `subflow_count == 0`.

---

## TCP-Specific Features

### 73. FWD Init Win Bytes

- **Type**: Integer (bytes)
- **Description**: TCP window size of first forward packet
- **Range**: 0-65535 (standard), higher with window scaling
- **Use**: Initial receive window analysis, OS fingerprinting

### 74. Bwd Init Win Bytes

- **Type**: Integer (bytes)
- **Description**: TCP window size of first backward packet
- **Use**: Server window size, congestion control analysis

### 75. Fwd Act Data Pkts

- **Type**: Integer
- **Description**: Forward packets with payload (excluding pure ACKs)
- **Condition**: `payload_bytes >= 1`
- **Use**: Actual data transfer vs. control packets

### 76. Fwd Seg Size Min

- **Type**: Integer (bytes)
- **Description**: Minimum header size in forward direction
- **Use**: Protocol overhead, encapsulation detection

---

## Active/Idle Time Features

Based on activity timeout (default: 5 seconds).

### 77. Active Mean

- **Type**: Float (microseconds)
- **Description**: Average duration of active periods
- **Active Period**: Consecutive packets within activity timeout
- **Use**: Session activity pattern

### 78. Active Std

- **Type**: Float (microseconds)
- **Description**: Standard deviation of active period durations
- **Use**: Activity regularity

### 79. Active Max

- **Type**: Float (microseconds)
- **Description**: Maximum active period duration
- **Use**: Longest burst detection

### 80. Active Min

- **Type**: Float (microseconds)
- **Description**: Minimum active period duration
- **Use**: Shortest burst detection

### 81. Idle Mean

- **Type**: Float (microseconds)
- **Description**: Average duration of idle periods
- **Idle Period**: Gap > activity timeout between packets
- **Use**: Think time, user interaction patterns

### 82. Idle Std

- **Type**: Float (microseconds)
- **Description**: Standard deviation of idle period durations
- **Use**: Idle period regularity

### 83. Idle Max

- **Type**: Float (microseconds)
- **Description**: Maximum idle period duration
- **Use**: Longest silence detection

### 84. Idle Min

- **Type**: Float (microseconds)
- **Description**: Minimum idle period duration
- **Use**: Shortest silence detection

**Note**: Active/Idle features are 0 if no active/idle periods detected.

---

## Label

### 85. Label

- **Type**: String
- **Default**: Empty
- **Description**: Ground truth label for supervised learning
- **Common Values**: `benign`, `DoS`, `PortScan`, `Botnet`, etc.
- **Use**: Classification target variable

**Note**: TriFlowMeter does not assign labels. This field is left empty for post-processing or manual labeling.

---

## Feature Computation Notes

### Welford's Algorithm

Running statistics (mean, variance, stddev) use Welford's method for numerical stability and single-pass computation.

### Division by Zero

All division operations check for zero denominators and return 0 in such cases.

### Missing Values

Features dependent on specific conditions (e.g., forward IAT when forward_packets <= 1) return 0.

### Precision

Floating-point values are formatted using Java-compatible number formatting for consistency with CICFlowMeter.

---

| Feature Type | Unit                           |
| ------------ | ------------------------------ |
| Time         | Microseconds (μs)              |
| Size         | Bytes                          |
| Rate         | Bytes/second or Packets/second |
| Count        | Integer (dimensionless)        |
| Ratio        | Float (dimensionless)          |

**Conversion**:

- Microseconds to seconds: divide by 1,000,000
- Bytes to kilobytes: divide by 1,024
- Bytes to megabytes: divide by 1,048,576

---

## Version Compatibility

These feature descriptions match:

- **TriFlowMeter**: All versions

For compatibility with other tools, ensure column order and naming conventions match.

---

_This feature documentation is maintained under GPL-3.0 license._
