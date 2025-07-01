#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "capture/pcap_reader.hpp"

std::vector<uint8_t> derive_ptk(
    const std::vector<uint8_t>& pmk,
    const uint8_t* ap_mac,
    const uint8_t* client_mac,
    const uint8_t* anonce,
    const uint8_t* snonce
);

bool validate_mic(
    const std::vector<uint8_t>& ptk,
    const uint8_t* eapol_frame,
    size_t eapol_len,
    const uint8_t* expected_mic,
    bool mic_is_sha1
);
