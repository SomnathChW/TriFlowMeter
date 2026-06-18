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

This document provides detailed descriptions of all **60 columns** exported by TriFlowMeter for each network flow. Columns are listed in exact CSV output order as defined in `CSVWriter.cpp`.

## Feature Categories

1. [Flow Metadata](#flow-metadata) (9 columns)
2. [Base Volumetrics](#base-volumetrics) (2 columns)
3. [Rates & Ratios](#rates--ratios) (5 columns)
4. [Packet Size Profiles — Forward](#packet-size-profiles--forward) (4 columns)
5. [Packet Size Profiles — Backward](#packet-size-profiles--backward) (4 columns)
6. [Packet Size Profiles — Total](#packet-size-profiles--total) (4 columns)
7. [Inter-Arrival Time Profiles — Forward](#inter-arrival-time-profiles--forward) (4 columns)
8. [Inter-Arrival Time Profiles — Backward](#inter-arrival-time-profiles--backward) (4 columns)
9. [Inter-Arrival Time Profiles — Flow](#inter-arrival-time-profiles--flow) (4 columns)
10. [TCP Flag Rates](#tcp-flag-rates) (6 columns)
11. [TCP/IP Mechanics — Window & Segment](#tcpip-mechanics--window--segment) (3 columns)
12. [TCP/IP Mechanics — TTL](#tcpip-mechanics--ttl) (2 columns)
13. [Connection States — Active](#connection-states--active) (4 columns)
14. [Connection States — Idle](#connection-states--idle) (4 columns)
15. [Label](#label) (1 column)

---

## Flow Metadata

### 1. Flow ID

- **CSV Header**: `Flow ID`
- **Type**: String
- **Format**: `{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}`
- **Description**: Unique identifier for the flow in forward direction
- **Example**: `192.168.1.10-8.8.8.8-52341-53-17`
- **Source**: `BasicPacketInfo::fwdFlowId()`

### 2. Src IP

- **CSV Header**: `Src IP`
- **Type**: String (IPv4 or IPv6)
- **Description**: Source IP address (originator of the flow)
- **Example**: `192.168.1.10` or `2001:db8::1`

### 3. Src Port

- **CSV Header**: `Src Port`
- **Type**: Integer (0–65535)
- **Description**: Source port number

### 4. Dst IP

- **CSV Header**: `Dst IP`
- **Type**: String (IPv4 or IPv6)
- **Description**: Destination IP address

### 5. Dst Port

- **CSV Header**: `Dst Port`
- **Type**: Integer (0–65535)
- **Description**: Destination port number

### 6. Protocol

- **CSV Header**: `Protocol`
- **Type**: Integer
- **Values**: `6` (TCP), `17` (UDP)
- **Description**: IP protocol number

### 7. Flow Start Time

- **CSV Header**: `Flow Start Time`
- **Type**: String
- **Format**: `DD/MM/YYYY HH:MM:SS AM/PM`
- **Description**: Human-readable timestamp of the first packet in the flow
- **Example**: `27/03/2026 08:45:32 PM`
- **Source**: `BasicFlow::getTimestampString()`

### 8. Flow End Time

- **CSV Header**: `Flow End Time`
- **Type**: String
- **Format**: `DD/MM/YYYY HH:MM:SS AM/PM`
- **Description**: Human-readable timestamp of the last packet in the flow
- **Source**: `BasicFlow::getFlowEndTimeString()`

### 9. Flow Duration

- **CSV Header**: `Flow Duration`
- **Type**: Integer (microseconds)
- **Description**: Total duration from first to last packet
- **Formula**: `flow_last_seen - flow_start_time`
- **Source**: `BasicFlow::getDuration()`

---

## Base Volumetrics

### 10. Total Fwd Packets

- **CSV Header**: `Total Fwd Packets`
- **Type**: Integer
- **Description**: Number of packets in forward direction (src → dst)

### 11. Total Bwd Packets

- **CSV Header**: `Total Bwd Packets`
- **Type**: Integer
- **Description**: Number of packets in backward direction (dst → src)

---

## Rates & Ratios

All rate features return `0.0` when flow duration is zero.

### 12. Flow Packets/s

- **CSV Header**: `Flow Packets/s`
- **Type**: Float (packets/second)
- **Formula**: `total_packets / duration_sec`

### 13. Payload Bytes/s

- **CSV Header**: `Payload Bytes/s`
- **Type**: Float (bytes/second)
- **Formula**: `total_payload_bytes / duration_sec`

### 14. Payload Ratio

- **CSV Header**: `Payload Ratio`
- **Type**: Float
- **Description**: Ratio of backward bytes to forward bytes
- **Formula**: `backward_bytes / forward_bytes` (0 if `forward_bytes == 0`)
- **Use**: Asymmetry detection (download-heavy vs upload-heavy)

### 15. Packet Count Ratio

- **CSV Header**: `Packet Count Ratio`
- **Type**: Float
- **Description**: Ratio of backward packets to forward packets
- **Formula**: `backward_packets / forward_packets` (0 if `forward_packets == 0`)

### 16. Header-to-Total Ratio

- **CSV Header**: `Header-to-Total Ratio`
- **Type**: Float
- **Description**: Fraction of total traffic that is protocol overhead
- **Formula**: `total_header_bytes / (total_bytes + total_header_bytes)` (0 if denominator is 0)
- **Use**: Protocol overhead analysis, tunneling detection

---

## Packet Size Profiles — Forward

All features in this group return `0` when no forward packets exist.

### 17. Fwd Pkt Len Min

- **CSV Header**: `Fwd Pkt Len Min`
- **Type**: Float (bytes)
- **Description**: Minimum payload size of forward packets

### 18. Fwd Pkt Len Max

- **CSV Header**: `Fwd Pkt Len Max`
- **Type**: Float (bytes)
- **Description**: Maximum payload size of forward packets

### 19. Fwd Pkt Len Mean

- **CSV Header**: `Fwd Pkt Len Mean`
- **Type**: Float (bytes)
- **Description**: Mean payload size of forward packets

### 20. Fwd Pkt Len Std

- **CSV Header**: `Fwd Pkt Len Std`
- **Type**: Float (bytes)
- **Description**: Standard deviation of forward packet payload sizes

---

## Packet Size Profiles — Backward

All features in this group return `0` when no backward packets exist.

### 21. Bwd Pkt Len Min

- **CSV Header**: `Bwd Pkt Len Min`
- **Type**: Float (bytes)

### 22. Bwd Pkt Len Max

- **CSV Header**: `Bwd Pkt Len Max`
- **Type**: Float (bytes)

### 23. Bwd Pkt Len Mean

- **CSV Header**: `Bwd Pkt Len Mean`
- **Type**: Float (bytes)

### 24. Bwd Pkt Len Std

- **CSV Header**: `Bwd Pkt Len Std`
- **Type**: Float (bytes)

---

## Packet Size Profiles — Total

Statistics across all packets in both directions.

### 25. Pkt Len Min

- **CSV Header**: `Pkt Len Min`
- **Type**: Float (bytes)

### 26. Pkt Len Max

- **CSV Header**: `Pkt Len Max`
- **Type**: Float (bytes)

### 27. Pkt Len Mean

- **CSV Header**: `Pkt Len Mean`
- **Type**: Float (bytes)

### 28. Pkt Len Std

- **CSV Header**: `Pkt Len Std`
- **Type**: Float (bytes)

---

## Inter-Arrival Time Profiles — Forward

IAT = time gap between consecutive packets in the same direction. All features return `0` when `forward_packets ≤ 1`.

### 29. Fwd IAT Min

- **CSV Header**: `Fwd IAT Min`
- **Type**: Float (microseconds)

### 30. Fwd IAT Max

- **CSV Header**: `Fwd IAT Max`
- **Type**: Float (microseconds)

### 31. Fwd IAT Mean

- **CSV Header**: `Fwd IAT Mean`
- **Type**: Float (microseconds)

### 32. Fwd IAT Std

- **CSV Header**: `Fwd IAT Std`
- **Type**: Float (microseconds)

---

## Inter-Arrival Time Profiles — Backward

All features return `0` when `backward_packets ≤ 1`.

### 33. Bwd IAT Min

- **CSV Header**: `Bwd IAT Min`
- **Type**: Float (microseconds)

### 34. Bwd IAT Max

- **CSV Header**: `Bwd IAT Max`
- **Type**: Float (microseconds)

### 35. Bwd IAT Mean

- **CSV Header**: `Bwd IAT Mean`
- **Type**: Float (microseconds)

### 36. Bwd IAT Std

- **CSV Header**: `Bwd IAT Std`
- **Type**: Float (microseconds)

---

## Inter-Arrival Time Profiles — Flow

IAT across all packets regardless of direction. Returns `0` when flow has only 1 packet.

### 37. Flow IAT Min

- **CSV Header**: `Flow IAT Min`
- **Type**: Float (microseconds)

### 38. Flow IAT Max

- **CSV Header**: `Flow IAT Max`
- **Type**: Float (microseconds)

### 39. Flow IAT Mean

- **CSV Header**: `Flow IAT Mean`
- **Type**: Float (microseconds)

### 40. Flow IAT Std

- **CSV Header**: `Flow IAT Std`
- **Type**: Float (microseconds)

---

## TCP Flag Rates

Rate of each TCP flag, normalized by total packets in the flow (`flag_count / total_packets`). These are duration-invariant features crucial for ML classification.

### 41. SYN Flag Rate

- **CSV Header**: `SYN Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of connection establishment requests

### 42. ACK Flag Rate

- **CSV Header**: `ACK Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of acknowledgments

### 43. FIN Flag Rate

- **CSV Header**: `FIN Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of connection termination requests

### 44. RST Flag Rate

- **CSV Header**: `RST Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of connection resets

### 45. PSH Flag Rate

- **CSV Header**: `PSH Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of push flags

### 46. URG Flag Rate

- **CSV Header**: `URG Flag Rate`
- **Type**: Float (0.0 to 1.0)
- **Description**: Rate of urgent flags

---

## TCP/IP Mechanics — Window & Segment

### 47. Fwd Init Win Size

- **CSV Header**: `Fwd Init Win Size`
- **Type**: Integer (bytes)
- **Description**: TCP window size from the first forward packet (SYN)
- **Use**: OS fingerprinting, initial receive buffer analysis

### 48. Bwd Init Win Size

- **CSV Header**: `Bwd Init Win Size`
- **Type**: Integer (bytes)
- **Description**: TCP window size from the first backward packet (SYN-ACK)

### 49. Fwd Min Segment Size

- **CSV Header**: `Fwd Min Segment Size`
- **Type**: Integer (bytes)
- **Description**: Minimum TCP/UDP header size observed in forward packets
- **Source**: `BasicFlow::min_seg_size_forward`

---

## TCP/IP Mechanics — TTL

### 50. Fwd Initial TTL

- **CSV Header**: `Fwd Initial TTL`
- **Type**: Integer (0–255)
- **Description**: IP TTL (Time-to-Live) / Hop Limit from the first forward packet
- **Use**: OS fingerprinting, path length estimation

### 51. Bwd Initial TTL

- **CSV Header**: `Bwd Initial TTL`
- **Type**: Integer (0–255)
- **Description**: IP TTL / Hop Limit from the first backward packet

---

## Connection States — Active

Active periods are consecutive packet sequences where inter-packet gaps stay within the activity timeout (default: 5 seconds). All features return `0` when no active periods have been recorded.

### 52. Active Min

- **CSV Header**: `Active Min`
- **Type**: Float (microseconds)
- **Description**: Minimum active period duration

### 53. Active Max

- **CSV Header**: `Active Max`
- **Type**: Float (microseconds)
- **Description**: Maximum active period duration

### 54. Active Mean

- **CSV Header**: `Active Mean`
- **Type**: Float (microseconds)
- **Description**: Average active period duration

### 55. Active Std

- **CSV Header**: `Active Std`
- **Type**: Float (microseconds)
- **Description**: Standard deviation of active period durations

---

## Connection States — Idle

Idle periods are gaps between active periods that exceed the activity timeout. All features return `0` when no idle periods have been recorded.

### 56. Idle Min

- **CSV Header**: `Idle Min`
- **Type**: Float (microseconds)
- **Description**: Minimum idle period duration

### 57. Idle Max

- **CSV Header**: `Idle Max`
- **Type**: Float (microseconds)
- **Description**: Maximum idle period duration

### 58. Idle Mean

- **CSV Header**: `Idle Mean`
- **Type**: Float (microseconds)
- **Description**: Average idle period duration

### 59. Idle Std

- **CSV Header**: `Idle Std`
- **Type**: Float (microseconds)
- **Description**: Standard deviation of idle period durations

---

## Label

### 60. Label

- **CSV Header**: `Label`
- **Type**: String
- **Default**: `Needs_Label`
- **Description**: Ground truth label assigned via the `--label` CLI flag
- **Common Values**: `Benign`, `DoS`, `PortScan`, `Botnet`, etc.
- **Note**: If no `--label` flag is provided, the value defaults to `Needs_Label`

---

## Feature Computation Notes

### Welford's Algorithm

Running statistics (mean, stddev) use Welford's method for numerical stability and single-pass computation. See `RunningStats` in `BasicFlow.h`.

### Division by Zero

All division operations check for zero denominators and return `0.0` in such cases.

### Missing Values

Features dependent on specific conditions (e.g., forward IAT when `forward_packets ≤ 1`) return `0`.

### Precision

Floating-point values are formatted using Java-compatible number formatting (`JavaNumberFormat.cpp`) to produce output consistent with CICFlowMeter conventions.

### Flow Export Threshold

Flows with `packetCount() <= 0` are not exported. During `finishAllFlows()`, remaining active flows with `packetCount() <= 1` are also skipped.

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

_This feature documentation is maintained under GPL-3.0 license._
