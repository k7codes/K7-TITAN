#include "k7titan/heuristic.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstring>
#include <string>
#include <unordered_set>

namespace k7titan {

double shannon_entropy(const uint8_t* data, size_t len) {
  if (!data || len == 0) return 0.0;
  size_t counts[256] = {0};
  for (size_t i = 0; i < len; ++i) counts[data[i]]++;
  double entropy = 0.0;
  for (size_t i = 0; i < 256; ++i) {
    if (!counts[i]) continue;
    double p = static_cast<double>(counts[i]) / static_cast<double>(len);
    entropy -= p * std::log2(p);
  }
  return entropy;
}

namespace {

bool contains_ci(const std::vector<uint8_t>& data, const std::string& needle) {
  if (needle.empty() || data.size() < needle.size()) return false;
  auto it = std::search(
      data.begin(), data.end(), needle.begin(), needle.end(),
      [](uint8_t a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                      std::tolower(static_cast<unsigned char>(b)); });
  return it != data.end();
}

const std::unordered_set<std::string>& suspicious_imports() {
  static const std::unordered_set<std::string> s = {
      "VirtualAlloc",     "VirtualAllocEx",    "VirtualProtect",   "WriteProcessMemory",
      "ReadProcessMemory", "CreateRemoteThread", "SetWindowsHookEx", "QueueUserAPC",
      "CreateProcessA",   "CreateProcessW",    "WinExec",          "ShellExecuteA",
      "ShellExecuteW",    "URLDownloadToFileA", "InternetOpenUrlA", "CryptEncrypt",
      "CryptDecrypt",     "IsDebuggerPresent", "CheckRemoteDebuggerPresent"};
  return s;
}

}  // namespace

HeuristicResult analyze_heuristics(const std::vector<uint8_t>& data, const PeInfo& pe) {
  HeuristicResult result;

  struct PatternRule {
    const char* pattern;
    const char* tag;
    float weight;
  };
  static const PatternRule kStringRules[] = {
      {"cmd.exe /c", "cmd-exec", 0.20f},
      {"powershell", "powershell", 0.20f},
      {"-enc ", "powershell-encoded", 0.25f},
      {"frombase64string", "base64-decode", 0.20f},
      {"downloadstring", "download-exec", 0.25f},
      {"net.webclient", "download-exec", 0.20f},
      {"createobject", "script-object", 0.15f},
      {"wscript.shell", "script-shell", 0.20f},
      {"schtasks", "persistence", 0.15f},
      {"reg add", "persistence", 0.15f},
      {"currentversion\\run", "autostart", 0.20f},
      {"http://", "url", 0.05f},
      {"https://", "url", 0.05f},
      {"bitcoin", "ransom-note", 0.25f},
      {"your files have been encrypted", "ransom-note", 0.60f},
      {"mimikatz", "credential-theft", 0.35f},
  };

  for (const auto& rule : kStringRules) {
    if (contains_ci(data, rule.pattern)) {
      result.score += rule.weight;
      result.tags.emplace_back(rule.tag);
    }
  }

  if (pe.is_valid) {
    if (pe.is_dotnet) result.tags.emplace_back("dotnet");

    int suspicious = 0;
    for (const auto& fn : pe.imported_functions) {
      if (suspicious_imports().count(fn)) {
        ++suspicious;
        result.tags.emplace_back("import:" + fn);
      }
    }
    if (suspicious >= 4) result.score += 0.30f;
    else if (suspicious >= 2) result.score += 0.15f;

    for (const auto& sec : pe.sections) {
      if (sec.is_writable() && sec.is_executable()) {
        result.score += 0.25f;
        result.tags.emplace_back("rwx-section");
      }
      if (sec.raw_size > 4096 && sec.entropy > 7.2) {
        result.score += 0.15f;
        result.tags.emplace_back("packed-section");
      }
      std::string lower = sec.name;
      std::transform(lower.begin(), lower.end(), lower.begin(),
                     [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (lower == "upx0" || lower == "upx1" || lower == ".packed" || lower == ".aspack") {
        result.score += 0.20f;
        result.tags.emplace_back("packer:" + lower);
      }
    }

    if (pe.entry_point_rva == 0) {
      result.score += 0.20f;
      result.tags.emplace_back("no-entrypoint");
    }
  } else if (data.size() > 4096) {
    double entropy = shannon_entropy(data.data(), data.size());
    if (entropy > 7.9) {
      result.score += 0.30f;
      result.tags.emplace_back("high-entropy");
    }
  }

  if (result.score > 1.0f) result.score = 1.0f;
  return result;
}

}
