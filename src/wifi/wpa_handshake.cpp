#include "wifi/wpa_handshake.hpp"
#include <openssl/hmac.h>
#include <cstring>

static void prf(const std::vector<uint8_t>& key,
                const std::string& label,
                const uint8_t* data, size_t data_len,
                uint8_t* output, size_t len) {
    size_t pos = 0;
    uint8_t counter = 0x01;

    while (pos < len) {
        std::vector<uint8_t> input(label.begin(), label.end());
        input.push_back(0x00); // null terminator
        input.insert(input.end(), data, data + data_len);
        input.push_back(counter);

        unsigned int out_len;
        uint8_t digest[EVP_MAX_MD_SIZE];

        HMAC(EVP_sha1(), key.data(), key.size(), input.data(), input.size(), digest, &out_len);

        size_t copy_len = std::min(len - pos, (size_t)out_len);
        std::memcpy(output + pos, digest, copy_len);

        pos += copy_len;
        counter++;
    }
}

std::vector<uint8_t> derive_ptk(const std::vector<uint8_t>& pmk,
                                const uint8_t* ap_mac,
                                const uint8_t* client_mac,
                                const uint8_t* anonce,
                                const uint8_t* snonce) {
    std::vector<uint8_t> ptk(64);
    uint8_t data[100];
    int i = 0;

    // MAC1 < MAC2
    if (std::memcmp(ap_mac, client_mac, 6) < 0) {
        std::memcpy(data + i, ap_mac, 6); i += 6;
        std::memcpy(data + i, client_mac, 6); i += 6;
    } else {
        std::memcpy(data + i, client_mac, 6); i += 6;
        std::memcpy(data + i, ap_mac, 6); i += 6;
    }

    // NONCE1 < NONCE2
    if (std::memcmp(anonce, snonce, 32) < 0) {
        std::memcpy(data + i, anonce, 32); i += 32;
        std::memcpy(data + i, snonce, 32); i += 32;
    } else {
        std::memcpy(data + i, snonce, 32); i += 32;
        std::memcpy(data + i, anonce, 32); i += 32;
    }

    prf(pmk, "Pairwise key expansion", data, i, ptk.data(), 64);
    return ptk;
}

bool validate_mic(const std::vector<uint8_t>& ptk,
                  const uint8_t* eapol_frame,
                  size_t eapol_len,
                  const uint8_t* expected_mic,
                  bool mic_is_sha1) {
    uint8_t computed_mic[20];
    uint8_t tmp_frame[4096];
    std::memcpy(tmp_frame, eapol_frame, eapol_len);

    // Zero out MIC field (offset 0x81 in many cases, but here we assume already zeroed externally)
    std::memset(tmp_frame + 0x81, 0x00, 16);

    unsigned int mic_len;
    HMAC(mic_is_sha1 ? EVP_sha1() : EVP_md5(), ptk.data(), 16, tmp_frame, eapol_len, computed_mic, &mic_len);

    return std::memcmp(computed_mic, expected_mic, 16) == 0;
}
