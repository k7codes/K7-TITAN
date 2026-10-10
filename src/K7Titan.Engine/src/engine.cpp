#include "k7titan/engine.hpp"
#include "k7titan/hasher.hpp"
#include "k7titan/heuristic.hpp"
#include "k7titan/pe.hpp"
#include "k7titan/rules.hpp"

#include <cstdlib>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace k7titan {

namespace {

constexpr size_t kMaxScanBytes = 64ull * 1024 * 1024;

thread_local std::string g_threat_name;

const std::unordered_set<std::string>& known_malicious_sha256() {
  static const std::unordered_set<std::string> db = {
      // EICAR Anti-Malware Test File
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  };
  return db;
}

constexpr const char* kEicarSignature = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

bool read_file(const std::string& path, std::vector<uint8_t>& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return false;
  in.seekg(0, std::ios::end);
  std::streamoff size = in.tellg();
  if (size < 0 || static_cast<size_t>(size) > kMaxScanBytes) return false;
  in.seekg(0, std::ios::beg);
  out.resize(static_cast<size_t>(size));
  if (size > 0) in.read(reinterpret_cast<char*>(out.data()), size);
  return true;
}

void set_result(ScanResult* out, ScanVerdict verdict, const std::string& name, float score) {
  out->verdict = verdict;
  g_threat_name = name;
  out->threat_name = g_threat_name.c_str();
  out->score = score;
}

std::string module_directory() {
#ifdef _WIN32
  char buf[MAX_PATH] = {0};
  if (GetModuleFileNameA(nullptr, buf, MAX_PATH) == 0) return {};
  std::string path(buf);
  auto slash = path.find_last_of("\\/");
  return slash == std::string::npos ? std::string{} : path.substr(0, slash);
#else
  return {};
#endif
}

RuleEngine& rule_engine() {
  static RuleEngine engine;
  return engine;
}

}  // namespace

extern "C" {

K7TITAN_API void K7tInitEngine() {
  RuleEngine& engine = rule_engine();

  if (const char* env = std::getenv("K7TITAN_RULES_DIR")) {
    engine.load_directory(env);
    return;
  }

  const std::string dir = module_directory();
  if (!dir.empty()) {
    engine.load_directory(dir + "\\rules");
  }
  engine.load_directory("rules");
}

K7TITAN_API void K7tShutdownEngine() {}

K7TITAN_API int K7tScanFile(const char* path, ScanResult* out_result) {
  if (!path || !out_result) return -1;

  out_result->verdict = ScanVerdict::Unknown;
  out_result->threat_name = "None";
  out_result->score = 0.0f;

  std::vector<uint8_t> data;
  if (!read_file(path, data)) {
    out_result->verdict = ScanVerdict::Unknown;
    return -2;
  }

  const std::string digest = sha256_hex(data);
  if (!digest.empty() && known_malicious_sha256().count(digest)) {
    set_result(out_result, ScanVerdict::Malicious, "EICAR-Test-File", 1.0f);
    return 0;
  }

  if (data.size() >= 68) {
    std::string head(reinterpret_cast<const char*>(data.data()),
                     data.size() < 256 ? data.size() : 256);
    if (head.find(kEicarSignature) != std::string::npos) {
      set_result(out_result, ScanVerdict::Malicious, "EICAR-Test-File.Sig", 1.0f);
      return 0;
    }
  }

  if (auto m = rule_engine().match(data)) {
    const ScanVerdict verdict =
        m->score >= 0.90f ? ScanVerdict::Malicious : ScanVerdict::Suspicious;
    set_result(out_result, verdict, m->rule_name, m->score);
    return 0;
  }

  const PeInfo pe = parse_pe(data);
  const HeuristicResult heuristics = analyze_heuristics(data, pe);

  if (heuristics.score >= 0.85f) {
    const std::string tag = heuristics.tags.empty() ? "Generic" : heuristics.tags.front();
    set_result(out_result, ScanVerdict::Malicious, "Heuristic." + tag, heuristics.score);
    return 0;
  }
  if (heuristics.score >= 0.40f) {
    const std::string tag = heuristics.tags.empty() ? "Generic" : heuristics.tags.front();
    set_result(out_result, ScanVerdict::Suspicious, "Heuristic." + tag, heuristics.score);
    return 0;
  }

  set_result(out_result, ScanVerdict::Clean, "None", heuristics.score);
  return 0;
}

}

}
