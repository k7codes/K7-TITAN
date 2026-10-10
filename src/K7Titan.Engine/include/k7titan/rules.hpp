#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace k7titan {

struct Rule {
  std::string name;
  std::vector<std::string> patterns;
  bool match_all = false;
  bool nocase = true;
  float score = 0.75f;
};

struct RuleMatch {
  std::string rule_name;
  size_t matched_patterns = 0;
  float score = 0.0f;
};

class RuleEngine {
 public:
  RuleEngine();

  void load_builtin();
  size_t load_file(const std::string& path);
  size_t load_directory(const std::string& dir);

  std::optional<RuleMatch> match(const std::vector<uint8_t>& data) const;

  size_t rule_count() const { return rules_.size(); }

 private:
  std::vector<Rule> rules_;
};

}
