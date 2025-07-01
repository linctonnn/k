#include "capture/pcap_reader.hpp"
#include <iostream>

WPAHandshake parse_pcap(const std::string& path) {
    std::cout << "[*] (stub) Parsing PCAP: " << path << std::endl;

    WPAHandshake hs;
    // TODO: Implement libpcap parsing here

    return hs;
}
