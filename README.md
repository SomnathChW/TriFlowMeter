# TriFlowMeter

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

> **Note:**
> CICFlowMeter Compatible output is only valid till v0.0.1. If you need compatibilty, use version v0.0.1.

TriFlowMeter is a high-performance network flow analyzer that extracts statistical features from network traffic for machine learning applications, intrusion detection, and network behavior analysis. It processes PCAP files or captures live network traffic and generates comprehensive flow-level statistics in CSV format.

## Overview

TriFlowMeter converts raw packet data into bidirectional network flows with rich statistical features. Each flow represents a communication session between two endpoints, characterized by the 5-tuple: source IP, destination IP, source port, destination port, and protocol.

### Key Features

- **High-Performance Processing**: Optimized C++17 implementation with optional CPU-specific optimizations
- **Dual Mode Operation**: Process PCAP files or capture live network traffic
- **Comprehensive Flow Statistics**: Extracts 83+ features per flow including timing, size, flags, and behavioral metrics
- **Bidirectional Flow Analysis**: Tracks forward and backward packet statistics separately
- **Real-time Dashboard**: Live monitoring interface with packet/flow statistics
- **Streaming Output**: Continuous CSV output for online analysis
- **Subflow Detection**: Automatic detection of activity periods within flows
- **Bulk Transfer Analysis**: Identifies and characterizes bulk data transfers

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

- Install [Npcap](https://npcap.com/) with SDK

### Compilation

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

For optimized builds:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DTRIFLOWMETER_ENABLE_NATIVE_OPT=ON ..
make -j$(nproc)
```

## Usage

### PCAP File Analysis

```bash
./triflowmeter input.pcap -o output.csv
```

### Live Capture

```bash
sudo ./triflowmeter -i eth0 -o live_flows.csv
```

### Streaming to stdout

```bash
./triflowmeter input.pcap --stdout
```

### Command-Line Options

- `-i <interface>` - Capture from network interface (requires root/admin)
- `-o <output>` - Specify output CSV file path
- `--stdout` - Write CSV to standard output
- `--flow-timeout <seconds>` - Flow timeout duration (default: 120)
- `--activity-timeout <seconds>` - Activity timeout for idle/active detection (default: 5)

## Output Format

TriFlowMeter generates CSV files with 84 columns per flow, including:

- **Flow Identification**: Flow ID, source/destination IPs, ports, protocol
- **Temporal Features**: Duration, timestamps, inter-arrival times
- **Size Features**: Packet/byte counts, length statistics
- **TCP Flags**: Counts for SYN, FIN, RST, PSH, ACK, URG, CWR, ECE
- **Behavioral Features**: Bulk transfer metrics, subflow statistics
- **Statistical Metrics**: Mean, standard deviation, min/max for various attributes

> **Note:**
> For CICFlowMeter-compatible CSV output, use the v0.0.1 tag/release. If you require CICFlowMeter compatibility, download or checkout the v0.0.1 release.

See [docs/FEATURES.md](docs/FEATURES.md) for detailed feature descriptions.

## Architecture

TriFlowMeter employs a modular pipeline architecture:

1. **Packet Capture**: libpcap-based reader with live/offline modes
2. **Packet Decoding**: Extracts IP/TCP/UDP headers and flags
3. **Flow Generation**: Bidirectional flow aggregation with timeout-based termination
4. **Feature Extraction**: Real-time statistical computation
5. **CSV Export**: Streaming output writer

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architectural documentation.

## Applications

- **Network Security**: Intrusion detection system (IDS) feature generation
- **Traffic Classification**: Application identification and QoS
- **Anomaly Detection**: Behavioral analysis and outlier detection
- **ML Training**: Dataset generation for supervised/unsupervised learning
- **Network Forensics**: Post-incident analysis and investigation

## Performance

- Processes 100K+ packets/second on modern hardware
- Memory-efficient streaming architecture
- Minimal overhead for live capture scenarios
- Zero-copy packet processing where possible

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
  url={https://github.com/SomnathChW},
  license={GPL-3.0}
}
```

## Acknowledgments

TriFlowMeter is inspired by CICFlowMeter and implements bidirectional flow analysis with performance optimizations and enhanced feature extraction.

## Support

For issues, questions, or contributions:

- Open an issue on the project repository
- Check existing documentation in ARCHITECTURE.md and FEATURES.md
- Review the source code documentation

---

**License Notice**: This software is distributed under GPL-3.0. Any derivative work must also be released under GPL-3.0 or a compatible license.
