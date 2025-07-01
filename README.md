# wifi-bruteforce

tool buat nyoba bruteforce wifi wpa/wpa2 pake c++  
gak pake aircrack-ng, gak pake python  
harus linux karena pake pcap & iw

## fitur

-   auto masuk monitor mode
-   scan ssid & bssid (beacon sniff)
-   pilih target wifi
-   generate PMK dari password & SSID
-   struktur pake cmake (biar keren dikit)

## build

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

## RUN

```bash
sudo ./wifi_bruteforce
```

## Dependensi

-   libpcap-dev
-   compiler c++17 ke atas
-   iw, iproute2

## Status

- [x] scan wifi
- [x] auto monitor mode
- [x] pmk generator (pbkdf2)
- [ ] parse .cap
- [ ] brute pake wordlist
- [ ] live capture handshake
- [ ] threading
