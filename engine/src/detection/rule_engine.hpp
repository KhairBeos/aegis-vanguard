#pragma once
// engine/src/detection/rule_engine.hpp
// Owns the ordered list of detection rules and evaluates each ParsedEvent
// against all rules, collecting zero or more RuleMatch results.

#include <memory>
#include <string>
#include <vector>

#include "detection/rule.hpp"
#include "types.hpp"

namespace aegis::detection {

class RuleEngine {
public:
    // Initialise with all built-in rules pre-registered.
    RuleEngine();

    // Register an additional rule (useful for testing or plugin rules).
    void add_rule(std::unique_ptr<BaseRule> rule);

    // Load external YAML-based rules from a directory.
    // Returns the number of successfully loaded rules.
    std::size_t load_external_rules_from_dir(const std::string& dir_path);

    // Evaluate all rules against a single event.
    // Returns one RuleMatch per matching rule (multiple rules can fire).
    std::vector<RuleMatch> evaluate(const ParsedEvent& event) const;

    // Evaluate all rules against a batch of events.
    // Returns all RuleMatch results across the entire batch.
    std::vector<RuleMatch> evaluate_batch(const std::vector<ParsedEvent>& events) const;

    std::size_t rule_count() const noexcept { return rules_.size(); }

private:
    std::vector<std::unique_ptr<BaseRule>> rules_;
};

}  // namespace aegis::detection
