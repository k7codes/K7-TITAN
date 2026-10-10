#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "k7titan/pe.hpp"

namespace k7titan {

double shannon_entropy(const uint8_t* data, size_t len);

struct HeuristicResult {
  float score = 0.0f;
  std::vector<std::string> tags;
};

HeuristicResult analyze_heuristics(const std::vector<uint8_t>& data, const PeInfo& pe);

}
