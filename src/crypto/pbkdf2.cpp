#include "crypto/pbkdf2.hpp"
#include <openssl/evp.h>

std::vector<uint8_t> derive_pmk(const std::string& passphrase, const std::string& ssid) {
    std::vector<uint8_t> pmk(32);

    PKCS5_PBKDF2_HMAC_SHA1(
        passphrase.c_str(), passphrase.length(),
        reinterpret_cast<const unsigned char*>(ssid.c_str()), ssid.length(),
        4096, 32,
        pmk.data()
    );

    return pmk;
}
