#pragma once
#include <string>
#include <vector>

struct AccessPoint {
    std::string ssid;
    std::string bssid;
    int channel;
    int signal_dbm;
};

std::vector<AccessPoint> scan_wifi(const std::string& interface, int timeout_sec = 5);
