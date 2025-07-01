#pragma once

#include <string>
#include <vector>
#include <cstdint>

struct WPAHandshake {
    std::string ssid;
    uint8_t ap_mac[6];
    uint8_t client_mac[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t eapol[256];
    size_t eapol_len;
    uint8_t mic[16];
    bool mic_is_sha1 = true;
};

WPAHandshake parse_pcap(const std::string& path);