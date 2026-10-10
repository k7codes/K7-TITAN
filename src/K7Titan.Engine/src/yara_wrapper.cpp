#include "k7titan/rules.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace k7titan {

namespace {

std::string read_text(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

std::string unescape_yara(const std::string& raw) {
  std::string out;
  out.reserve(raw.size());
  for (size_t i = 0; i < raw.size(); ++i) {
    if (raw[i] == '\\' && i + 1 < raw.size()) {
      char n = raw[i + 1];
      switch (n) {
        case '\\': out.push_back('\\'); ++i; break;
        case '"': out.push_back('"'); ++i; break;
        case 'n': out.push_back('\n'); ++i; break;
        case 't': out.push_back('\t'); ++i; break;
        case 'r': out.push_back('\r'); ++i; break;
        default: out.push_back(raw[i]); break;
      }
    } else {
      out.push_back(raw[i]);
    }
  }
  return out;
}

std::string between_quotes(const std::string& block, const std::string& key) {
  auto k = block.find(key);
  if (k == std::string::npos) return {};
  auto q = block.find('"', k);
  if (q == std::string::npos) return {};
  auto e = block.find('"', q + 1);
  if (e == std::string::npos) return {};
  return block.substr(q + 1, e - q - 1);
}

bool ci_contains(const std::vector<uint8_t>& data, const std::string& needle) {
  if (needle.empty() || data.size() < needle.size()) return false;
  auto it = std::search(
      data.begin(), data.end(), needle.begin(), needle.end(),
      [](uint8_t a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                      std::tolower(static_cast<unsigned char>(b)); });
  return it != data.end();
}

bool cs_contains(const std::vector<uint8_t>& data, const std::string& needle) {
  if (needle.empty() || data.size() < needle.size()) return false;
  return std::search(data.begin(), data.end(), needle.begin(), needle.end()) != data.end();
}

}  // namespace

RuleEngine::RuleEngine() { load_builtin(); }

void RuleEngine::load_builtin() {
  rules_.clear();

  Rule eicar;
  eicar.name = "EICAR-Test-File";
  eicar.patterns = {"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"};
  eicar.match_all = true;
  eicar.score = 0.99f;
  rules_.push_back(std::move(eicar));

  Rule ps;
  ps.name = "Suspicious.PowerShell.DownloadExec";
  ps.patterns = {"powershell", "iex", "downloadstring"};
  ps.match_all = true;
  ps.score = 0.70f;
  rules_.push_back(std::move(ps));

  Rule cradle;
  cradle.name = "Suspicious.WebClient.Cradle";
  cradle.patterns = {"net.webclient", "downloadfile", "start-process"};
  cradle.match_all = true;
  cradle.score = 0.72f;
  rules_.push_back(std::move(cradle));

  Rule ransom;
  ransom.name = "Suspicious.RansomNote";
  ransom.patterns = {"your files have been encrypted"};
  ransom.match_all = true;
  ransom.score = 0.85f;
  rules_.push_back(std::move(ransom));

  Rule mimikatz;
  mimikatz.name = "HackTool.Mimikatz";
  mimikatz.patterns = {"sekurlsa", "kerberos::golden", "mimikatz"};
  mimikatz.match_all = true;
  mimikatz.score = 0.90f;
  rules_.push_back(std::move(mimikatz));
}

size_t RuleEngine::load_file(const std::string& path) {
  const std::string text = read_text(path);
  if (text.empty()) return 0;

  size_t loaded = 0;
  size_t pos = 0;
  while ((pos = text.find("rule ", pos)) != std::string::npos) {
    size_t name_start = pos + 5;
    while (name_start < text.size() && std::isspace(static_cast<unsigned char>(text[name_start]))) ++name_start;
    size_t name_end = name_start;
    while (name_end < text.size() &&
           (std::isalnum(static_cast<unsigned char>(text[name_end])) || text[name_end] == '_')) {
      ++name_end;
    }
    std::string name = text.substr(name_start, name_end - name_start);

    size_t brace = text.find('{', name_end);
    if (brace == std::string::npos) break;
    int depth = 1;
    size_t end = brace + 1;
    for (; end < text.size() && depth > 0; ++end) {
      if (text[end] == '{') ++depth;
      else if (text[end] == '}') --depth;
    }
    std::string block = text.substr(brace, end - brace);
    pos = end;

    if (name.empty()) continue;

    Rule rule;
    rule.name = name;
    rule.nocase = lower(block).find("nocase") != std::string::npos;

    size_t sp = 0;
    while ((sp = block.find('"', sp)) != std::string::npos) {
      size_t close = sp + 1;
      std::string raw;
      while (close < block.size() && block[close] != '"') {
        if (block[close] == '\\' && close + 1 < block.size()) {
          raw.push_back(block[close]);
          raw.push_back(block[close + 1]);
          close += 2;
          continue;
        }
        raw.push_back(block[close]);
        ++close;
      }
      if (close >= block.size()) break;
      std::string value = unescape_yara(raw);
      sp = close + 1;
      if (value == "test" || value == "high" || value == "medium" || value == "low" ||
          value == "K7 TITAN" || value.size() > 200 || lower(value).rfind("detect", 0) == 0 ||
          lower(value).rfind("pattern", 0) == 0 || lower(value).rfind("long", 0) == 0 ||
          lower(value).rfind("very", 0) == 0) {
        continue;  // meta description/keywords, not a pattern
      }
      rule.patterns.push_back(value);
    }

    if (rule.patterns.empty()) continue;

    std::string sev = lower(between_quotes(block, "severity"));
    std::string conf = lower(between_quotes(block, "confidence"));
    if (sev == "test" || sev == "high") rule.score = 0.95f;
    else if (sev == "medium") rule.score = 0.80f;
    else if (sev == "low") rule.score = 0.60f;
    if (conf == "low") rule.score = std::min(rule.score, 0.60f);

    std::string cond = lower(block);
    rule.match_all = cond.find(" or ") == std::string::npos &&
                     cond.find("any of") == std::string::npos;

    rules_.push_back(std::move(rule));
    ++loaded;
  }
  return loaded;
}

size_t RuleEngine::load_directory(const std::string& dir) {
  size_t total = 0;
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) return 0;
  for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) break;
    if (entry.is_regular_file()) {
      auto ext = lower(entry.path().extension().string());
      if (ext == ".yar" || ext == ".yara") {
        total += load_file(entry.path().string());
      }
    }
  }
  return total;
}

std::optional<RuleMatch> RuleEngine::match(const std::vector<uint8_t>& data) const {
  std::optional<RuleMatch> best;
  for (const auto& rule : rules_) {
    size_t matched = 0;
    for (const auto& p : rule.patterns) {
      bool hit = rule.nocase ? ci_contains(data, p) : cs_contains(data, p);
      if (hit) ++matched;
    }
    bool triggered = rule.match_all ? matched == rule.patterns.size() : matched > 0;
    if (!triggered) continue;

    float score = rule.score;
    if (rule.patterns.size() > 1 && matched == rule.patterns.size()) {
      score = std::min(1.0f, score + 0.05f);
    }

    RuleMatch m;
    m.rule_name = rule.name;
    m.matched_patterns = matched;
    m.score = score;
    if (!best || m.score > best->score) best = m;
  }
  return best;
}

}
