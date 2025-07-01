#include "capture/wifi_scanner.hpp"
#include <pcap.h>
#include <iostream>
#include <unordered_map>
#include <cstring>
#include <ctime>

static std::string mac_to_str(const uint8_t* mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::vector<AccessPoint> scan_wifi(const std::string& interface, int timeout_sec) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), 2048, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "[-] Failed to open interface: " << errbuf << std::endl;
        return {};
    }

    std::unordered_map<std::string, AccessPoint> aps;

    auto start = std::time(nullptr);
    while (std::time(nullptr) - start < timeout_sec) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res <= 0) continue;

        const u_char* radiotap = packet;
        int radiotap_len = radiotap[2] + (radiotap[3] << 8);

        const u_char* frame = packet + radiotap_len;
        if ((frame[0] & 0xF0) != 0x80) continue; // Only Beacon

        const uint8_t* bssid = frame + 16;
        std::string bssid_str = mac_to_str(bssid);

        const uint8_t* tags = frame + 36;
        int tag_len = header->caplen - (tags - packet);

        std::string ssid = "<hidden>";
        int channel = -1;
        int signal = 0;

        int i = 0;
        while (i + 2 < tag_len) {
            uint8_t tag_id = tags[i];
            uint8_t len = tags[i + 1];
            if (i + 2 + len > tag_len) break;

            if (tag_id == 0 && len > 0) {
                ssid = std::string((const char*)&tags[i + 2], len);
            } else if (tag_id == 3 && len == 1) {
                channel = tags[i + 2];
            }

            i += 2 + len;
        }

        AccessPoint ap{ssid, bssid_str, channel, signal};
        aps[bssid_str] = ap;
    }

    pcap_close(handle);

    std::vector<AccessPoint> results;
    for (const auto& [_, ap] : aps) results.push_back(ap);
    return results;
}
