#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace k7titan {

std::string sha256_hex(const std::vector<uint8_t>& data);
std::string sha256_hex_file(const std::string& path);
std::string md5_hex(const std::vector<uint8_t>& data);

}
