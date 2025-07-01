#include "capture/wifi_mode.hpp"
#include <cstdlib>
#include <iostream>

bool set_monitor_mode(const std::string& iface) {
    std::string cmd =
        "ip link set " + iface + " down && "
        "iw dev " + iface + " set type monitor && "
        "ip link set " + iface + " up";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "[-] Failed to set monitor mode on " << iface << "\n";
        return false;
    }

    std::cout << "[*] Monitor mode enabled on " << iface << "\n";
    return true;
}

bool restore_managed_mode(const std::string& iface) {
    std::string cmd =
        "ip link set " + iface + " down && "
        "iw dev " + iface + " set type managed && "
        "ip link set " + iface + " up";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "[-] Failed to restore managed mode on " << iface << "\n";
        return false;
    }

    std::cout << "[*] Managed mode restored on " << iface << "\n";
    return true;
}
