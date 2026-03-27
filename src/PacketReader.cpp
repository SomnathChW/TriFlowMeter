#include "PacketReader.h"

#include "PacketDecoders.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

struct ether_header {
    u_char ether_dhost[6];
    u_char ether_shost[6];
    u_short ether_type;
};

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP 0x0806
#endif

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86DD
#endif

#else
#include <netinet/if_ether.h>
#endif

PacketReader::PacketReader(Mode mode,
                                                     const std::string& source,
                                                     int snaplen,
                                                     bool promiscuous,
                                                     int timeout_ms)
        : mode_(mode),
            pcap_path_(source),
            handle_(nullptr),
            snaplen_(snaplen),
            promiscuous_(promiscuous),
            timeout_ms_(timeout_ms) {}

PacketReader::PacketReader(const std::string& pcap_path)
        : mode_(Mode::Offline),
            pcap_path_(pcap_path),
            handle_(nullptr),
            snaplen_(65535),
            promiscuous_(true),
            timeout_ms_(1000) {}

PacketReader::~PacketReader() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketReader::open() {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (mode_ == Mode::Offline) {
        handle_ = pcap_open_offline(pcap_path_.c_str(), errbuf);
    } else {
        handle_ = pcap_open_live(
            pcap_path_.c_str(),
            snaplen_,
            promiscuous_ ? 1 : 0,
            timeout_ms_,
            errbuf);
    }

    if (handle_ == nullptr) {
        last_error_ = errbuf;
        return false;
    }

    if (mode_ == Mode::Live && pcap_datalink(handle_) != DLT_EN10MB) {
        last_error_ = "live capture currently supports Ethernet interfaces only (DLT_EN10MB)";
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }

    return true;
}

bool PacketReader::readAll(FlowGenerator& flow_gen,
                           PacketStats& stats,
                           bool read_ipv4,
                           bool read_ipv6,
                           const volatile std::sig_atomic_t* stop_flag,
                           std::function<void(const PacketStats&)> packet_progress_cb) {
    if (handle_ == nullptr) {
        last_error_ = "packet reader is not open";
        return false;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;

    while (true) {
        if (stop_flag != nullptr && *stop_flag) {
            break;
        }

        const int rc = pcap_next_ex(handle_, &header, &packet);
        if (rc == 1) {
            // continue with packet decode below
        } else if (rc == 0) {
            // Live timeout tick.
            if (packet_progress_cb) {
                packet_progress_cb(stats);
            }
            continue;
        } else if (rc == -2) {
            // EOF (offline capture finished)
            break;
        } else {
            last_error_ = pcap_geterr(handle_);
            return false;
        }

        stats.total++;

        if (header->caplen < sizeof(struct ether_header)) {
            stats.discarded++;
            continue;
        }

        const struct ether_header* eth_header = reinterpret_cast<const struct ether_header*>(packet);
        const u_short eth_type = ntohs(eth_header->ether_type);

        const u_char* ip_packet = packet + sizeof(struct ether_header);
        const int remaining_len = static_cast<int>(header->caplen - sizeof(struct ether_header));

        bool valid = false;
        BasicPacketInfo packet_info;
        packet_info.timestamp_sec = header->ts.tv_sec;
        packet_info.timestamp_usec = header->ts.tv_usec;

        if (read_ipv4 && eth_type == ETHERTYPE_IP) {
            valid = packetdecode::decodeIPv4(ip_packet, remaining_len, &packet_info);
        }

        if (!valid && read_ipv6 && eth_type == ETHERTYPE_IPV6) {
            valid = packetdecode::decodeIPv6(ip_packet, remaining_len, &packet_info);
        }

        if (!valid && eth_type == ETHERTYPE_ARP) {
            valid = packetdecode::decodeArpCompat(eth_type, ip_packet, remaining_len, &packet_info);
        }

        // Java PacketReader falls back to VPN/L2TP parsing when direct IP parse fails.
        if (!valid) {
            valid = packetdecode::decodeL2TP(ip_packet, remaining_len);
            if (valid) {
                stats.vpn_packets++;
            }
        }

        if (valid) {
            stats.valid++;
            flow_gen.addPacket(packet_info);
        } else {
            stats.discarded++;
        }

        if (packet_progress_cb) {
            packet_progress_cb(stats);
        }
    }

    return true;
}

const std::string& PacketReader::getLastError() const {
    return last_error_;
}
