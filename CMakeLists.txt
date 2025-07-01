cmake_minimum_required(VERSION 3.14)
project(bruteforce)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add include directory
include_directories(include)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(OpenSSL REQUIRED)

# Source files
file(GLOB_RECURSE SRC_FILES src/*.cpp)

add_executable(wifi_bruteforce main.cpp ${SRC_FILES})

# Link libraries
target_include_directories(wifi_bruteforce PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(wifi_bruteforce PRIVATE ${PCAP_LIBRARIES} OpenSSL::Crypto)
