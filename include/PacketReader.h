#pragma once

#include <pcap.h>

#include <csignal>
#include <cstdint>
#include <functional>
#include <string>

#include "BasicPacketInfo.h"
#include "FlowGenerator.h"

class PacketReader {
public:
    enum class Mode {
        Offline,
        Live,
    };

    explicit PacketReader(const std::string& pcap_path);
    PacketReader(Mode mode, const std::string& source, int snaplen, bool promiscuous, int timeout_ms);
    ~PacketReader();

    bool open();
    bool readAll(FlowGenerator& flow_gen,
                 PacketStats& stats,
                 bool read_ipv4 = true,
                 bool read_ipv6 = true,
                 const volatile std::sig_atomic_t* stop_flag = nullptr,
                 std::function<void(const PacketStats&)> packet_progress_cb = nullptr);

    const std::string& getLastError() const;

private:
    Mode mode_;
    std::string pcap_path_;
    std::string last_error_;
    pcap_t* handle_;
    int snaplen_;
    bool promiscuous_;
    int timeout_ms_;
};
