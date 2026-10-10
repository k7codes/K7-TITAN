#pragma once

#ifdef _WIN32
#ifdef K7TITAN_ENGINE_EXPORTS
#define K7TITAN_API __declspec(dllexport)
#else
#define K7TITAN_API __declspec(dllimport)
#endif
#else
#define K7TITAN_API
#endif

#include <cstdint>
#include <string_view>

namespace k7titan {

enum class ScanVerdict : int {
  Clean = 0,
  Suspicious = 1,
  Malicious = 2,
  Unknown = 3
};

struct ScanResult {
  ScanVerdict verdict;
  const char* threat_name;
  float score;
};

extern "C" {
K7TITAN_API int K7tScanFile(const char* path, ScanResult* out_result);
K7TITAN_API void K7tInitEngine();
K7TITAN_API void K7tShutdownEngine();
}

}
