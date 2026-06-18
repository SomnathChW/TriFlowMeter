# TriFlowMeter

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

> **Note:**
> CICFlowMeter Compatible output is only valid till v0.0.1. If you need compatibility, use version v0.0.1.

TriFlowMeter is a high-performance network flow analyzer that extracts statistical features from network traffic for machine learning applications, intrusion detection, and network behavior analysis. It processes PCAP files or captures live network traffic and generates comprehensive flow-level statistics in CSV format.

## Overview

TriFlowMeter converts raw packet data into bidirectional network flows with rich statistical features. Each flow represents a communication session between two endpoints, characterized by the 5-tuple: source IP, destination IP, source port, destination port, and protocol.

### Key Features

- **High-Performance C++17**: Optimized with `-O3`, `-march=native`, and link-time optimization
- **Dual Mode Operation**: Process PCAP files (offline) or capture live network traffic
- **60-Column CSV Output**: Extracts 60 features per flow covering timing, size, flags, ratios, and behavioral metrics
- **Bidirectional Flow Analysis**: Tracks forward and backward packet statistics independently
- **Real-Time Dashboard**: Live terminal UI showing packet counts, flow progress, and uptime
- **Streaming Output**: `--stdout` mode for piping into downstream tools
- **IPv4 + IPv6 + L2TP**: Handles IPv4, IPv6, and L2TP/VPN-encapsulated packets
- **Active/Idle Detection**: Tracks activity periods within flows using configurable timeouts
- **Java-Compatible Formatting**: CSV numeric output matches CICFlowMeter conventions
- **Sudo-Aware**: Automatically restores file ownership when running under `sudo`

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

See the [LICENSE](LICENSE) file for the full license text.

## Building from Source

### Prerequisites

- CMake 3.16 or higher
- C++17 compatible compiler (GCC 7+, Clang 6+, MSVC 2017+)
- libpcap development files

**Linux/Ubuntu:**

```bash
sudo apt-get install build-essential cmake libpcap-dev
```

**macOS:**

```bash
brew install cmake libpcap
```

**Windows:**

To build natively without bloated IDEs:
1. Install the [Npcap Driver](https://npcap.com/) (you do **not** need the SDK zip).
2. Install a lightweight compiler, CMake, and the pcap headers via [MSYS2](https://www.msys2.org/). Once installed, open the MSYS2 terminal and run:
   ```bash
   pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake make mingw-w64-x86_64-libpcap
   ```

### Compilation

```bash
mkdir build
cd build
cmake ..
cmake --build . -j 4
```

For optimized builds (default is Release with native optimizations):

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DTRIFLOWMETER_ENABLE_NATIVE_OPT=ON ..
cmake --build . -j 4
```

To disable CPU-specific optimizations (for portable binaries):

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DTRIFLOWMETER_ENABLE_NATIVE_OPT=OFF ..
```

## Usage

### PCAP File Analysis

```bash
# Output to auto-named file (input_Flow.csv)
./triflowmeter input.pcap

# Output to a specific file
./triflowmeter input.pcap output.csv

# Output to a directory (creates dir/input_flows.csv)
./triflowmeter input.pcap results/
```

### Live Capture

```bash
# Capture from interface, output to auto-named file
sudo ./triflowmeter --live eth0

# Capture with explicit output path
sudo ./triflowmeter --live eth0 live_flows.csv

# Capture with a label for all flows
sudo ./triflowmeter --live eth0 output.csv --label Benign
```

### Streaming to stdout

```bash
# Pipe CSV rows to another tool
./triflowmeter input.pcap --stdout | python3 classify.py

# Live capture to stdout
sudo ./triflowmeter --live eth0 --stdout
```

### Command-Line Options

```
Usage:
  triflowmeter <pcap_file> [output_path_or_directory] [options]
  triflowmeter --live <interface> [output_path_or_directory] [options]

Options:
  --flow-timeout <sec>      Flow timeout in seconds (default: 120)
  --activity-timeout <sec>  Activity timeout in seconds (default: 5)
  --label <label>           Label for all flows (default: Needs_Label)
  --stdout                  Write CSV header/rows to stdout
  -h, --help                Show this help
```

| Option | Description | Default |
|--------|-------------|---------|
| `--live <interface>` | Capture from a live network interface (requires root) | — |
| `--stdout` | Write CSV to stdout instead of a file | Off |
| `--flow-timeout <sec>` | Maximum duration of a flow before it is split | `120` |
| `--activity-timeout <sec>` | Idle threshold for active/idle period detection | `5` |
| `--label <label>` | Ground truth label written to the Label column | `Needs_Label` |

> **Note:** `--stdout` and an output path cannot be used together.

## Output Format

TriFlowMeter generates CSV files with **60 columns** per flow:

| Category | Columns | Count |
|----------|---------|-------|
| Flow Metadata | Flow ID, Src/Dst IP, Ports, Protocol, Timestamps, Duration | 9 |
| Base Volumetrics | Fwd/Bwd Packets | 2 |
| Rates & Ratios | Flow Packets/s, Payload Bytes/s, Payload Ratio, Count Ratio, Header Ratio | 5 |
| Packet Size Profiles | Fwd/Bwd/Total Min, Max, Mean, Std | 12 |
| Inter-Arrival Times | Fwd/Bwd/Flow IAT Min, Max, Mean, Std | 12 |
| TCP Flag Rates | SYN, ACK, FIN, RST, PSH, URG Rates | 6 |
| TCP/IP Mechanics | Init Window Sizes, Min Segment Size, Initial TTL | 5 |
| Connection States | Active/Idle Min, Max, Mean, Std | 8 |
| Label | Ground truth label | 1 |

> **Note:**
> For CICFlowMeter-compatible CSV output, use the v0.0.1 tag/release.

See [docs/FEATURES.md](docs/FEATURES.md) for detailed feature descriptions with exact CSV header names.

## Architecture

TriFlowMeter employs a modular pipeline architecture:

```
PacketReader → PacketDecoders → FlowGenerator → CSVWriter
                                      │
                                 BasicFlow (per-flow statistics)
                                      │
                                 LiveDashboard (terminal UI)
```

1. **PacketReader**: libpcap-based reader with live/offline modes
2. **PacketDecoders**: Extracts IPv4/IPv6/TCP/UDP/L2TP headers and metadata
3. **FlowGenerator**: Bidirectional flow aggregation with timeout-based splitting
4. **BasicFlow**: Real-time statistical computation via Welford's algorithm
5. **CSVWriter**: 60-column streaming CSV serialization
6. **LiveDashboard**: Real-time terminal dashboard with packet/flow statistics

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architectural documentation.

## Protocols Supported

| Protocol | Status |
|----------|--------|
| IPv4 (TCP, UDP) | ✅ Fully supported |
| IPv6 (TCP, UDP) | ✅ Fully supported |
| L2TP / VPN tunnels | ✅ Decapsulated and decoded |
| ARP | ❌ Disabled (declared but not active) |
| ICMP | ❌ Not supported |

## Applications

- **Network Security**: Intrusion detection system (IDS) feature generation
- **Traffic Classification**: Application identification and QoS
- **Anomaly Detection**: Behavioral analysis and outlier detection
- **ML Training**: Dataset generation for supervised/unsupervised learning
- **Network Forensics**: Post-incident analysis and investigation

## Performance

- Streaming architecture with bounded memory usage
- Single-pass statistics (Welford's) — no per-packet storage
- FNV-1a hash-based flow lookup in O(1) average time
- Optional `-march=native` for CPU-specific optimizations
- Link-time optimization (`-flto`) in Release builds

## Contributing

Contributions are welcome! Please ensure:

- Code follows existing style conventions
- New features include appropriate tests
- Documentation is updated accordingly
- Commits are signed with GPL compliance

## Citation

If you use TriFlowMeter in academic research, please cite:

```bibtex
@software{triflowmeter,
  title={TriFlowMeter: High-Performance Network Flow Analyzer},
  author={Chowdhury, Somnath},
  year={2026},
  url={https://github.com/SomnathChW/TriFlowMeter},
  license={GPL-3.0}
}
```

## Acknowledgments

TriFlowMeter is inspired by CICFlowMeter and implements bidirectional flow analysis with performance optimizations and enhanced feature extraction.

## Support

For issues, questions, or contributions:

- Open an issue on the project repository
- Check existing documentation in [ARCHITECTURE.md](docs/ARCHITECTURE.md) and [FEATURES.md](docs/FEATURES.md)
- Review the source code documentation

---

**License Notice**: This software is distributed under GPL-3.0. Any derivative work must also be released under GPL-3.0 or a compatible license.
