#pragma once
#include <string>

bool set_monitor_mode(const std::string& iface);
bool restore_managed_mode(const std::string& iface);
