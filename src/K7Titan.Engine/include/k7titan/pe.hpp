#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace k7titan {

struct PeSection {
  std::string name;
  uint32_t virtual_address = 0;
  uint32_t virtual_size = 0;
  uint32_t raw_offset = 0;
  uint32_t raw_size = 0;
  uint32_t characteristics = 0;
  double entropy = 0.0;

  bool is_executable() const { return (characteristics & 0x20000000u) != 0; }
  bool is_writable() const { return (characteristics & 0x80000000u) != 0; }
};

struct PeInfo {
  bool is_valid = false;
  bool is_64bit = false;
  bool is_dotnet = false;
  uint16_t machine = 0;
  uint16_t number_of_sections = 0;
  uint32_t entry_point_rva = 0;
  uint32_t timestamp = 0;
  std::vector<PeSection> sections;
  std::vector<std::string> imported_dlls;
  std::vector<std::string> imported_functions;
};

PeInfo parse_pe(const std::vector<uint8_t>& data);

}
