#include <iostream>
#include <string>
#include <vector>
#include "capture/wifi_mode.hpp"
#include "capture/wifi_scanner.hpp"
#include "capture/pcap_reader.hpp"
#include "crypto/pbkdf2.hpp"
#include "wifi/wpa_handshake.hpp"

int main() {
    std::string interface = "wlp3s0";  // Change this to your actual wifi interface

    std::cout << "[*] Setting monitor mode on interface: " << interface << "\n";
    if (!set_monitor_mode(interface)) return 1;

    std::cout << "[*] Scanning nearby WiFi networks...\n";
    auto aps = scan_wifi(interface, 5);

    if (aps.empty()) {
        std::cerr << "[-] No access points found.\n";
        restore_managed_mode(interface);
        return 1;
    }

    std::cout << "\nAvailable WiFi networks:\n";
    for (size_t i = 0; i < aps.size(); ++i) {
        std::cout << "  [" << i << "] SSID: " << aps[i].ssid
                  << " | BSSID: " << aps[i].bssid
                  << " | Channel: " << aps[i].channel << "\n";
    }

    std::cout << "\nSelect target [0-" << aps.size() - 1 << "]: ";
    size_t index;
    std::cin >> index;

    if (index >= aps.size()) {
        std::cerr << "[-] Invalid index.\n";
        restore_managed_mode(interface);
        return 1;
    }

    std::string target_ssid = aps[index].ssid;
    std::string target_bssid = aps[index].bssid;
    std::cout << "[*] Selected: " << target_ssid << " (" << target_bssid << ")\n";

    // Placeholder: parse handshake capture file (belum diimplementasi)
    std::string cap_path = "data/handshake.cap";
    std::cout << "[*] Parsing handshake from: " << cap_path << "\n";
    auto handshake = parse_pcap(cap_path); // TODO implement this

    // Bruteforce test (placeholder password)
    std::string test_password = "password123";
    std::cout << "[*] Deriving PMK from password: " << test_password << "\n";
    auto pmk = derive_pmk(test_password, target_ssid);
    std::cout << "[+] PMK derived (" << pmk.size() << " bytes)\n";

    std::cout << "[*] Restoring interface to managed mode...\n";
    restore_managed_mode(interface);

    std::cout << "[+] Finished.\n";
    return 0;
}
