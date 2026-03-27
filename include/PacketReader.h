#pragma once

#include <pcap.h>

#include <string>

#include "BasicPacketInfo.h"
#include "FlowGenerator.h"

class PacketReader {
public:
    explicit PacketReader(const std::string& pcap_path);
    ~PacketReader();

    bool open();
    bool readAll(FlowGenerator& flow_gen,
                 PacketStats& stats,
                 bool read_ipv4 = true,
                 bool read_ipv6 = true);

    const std::string& getLastError() const;

private:
    std::string pcap_path_;
    std::string last_error_;
    pcap_t* handle_;
};
