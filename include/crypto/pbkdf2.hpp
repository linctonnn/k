#pragma once

#include <string>
#include <vector>
#include <cstdint>

std::vector<uint8_t> derive_pmk(const std::string& passphrase, const std::string& ssid);
