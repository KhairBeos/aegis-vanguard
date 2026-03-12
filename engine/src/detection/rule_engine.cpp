#include "detection/rule_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <deque>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <spdlog/spdlog.h>

namespace aegis::detection {

namespace {

struct ExternalCondition {
    std::string path;
    std::string op;
    std::string value;
};

struct ExternalRuleSpec {
    std::string id;
    std::string name;
    std::string event_type;
    Severity severity{Severity::Medium};
    uint32_t risk_score{60};
    std::string summary;
    std::string summary_template;
    std::vector<std::string> tags;
    bool match_any{false};
    int min_hits{1};
    int window_seconds{0};
    int alert_cooldown_seconds{0};
    std::vector<std::string> group_by;
    std::vector<ExternalCondition> conditions;
};

std::optional<ExternalRuleSpec> parse_sigma_style_rule_file(const std::filesystem::path& file_path);

std::string trim_copy(std::string value) {
    const auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), [&](unsigned char c) { return !is_space(c); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](unsigned char c) { return !is_space(c); }).base(),
                value.end());
    return value;
}

std::string unquote_copy(std::string value) {
    value = trim_copy(std::move(value));
    if (value.size() >= 2) {
        const char first = value.front();
        const char last = value.back();
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substr(1, value.size() - 2);
        }
    }
    return value;
}

bool parse_key_value(const std::string& line, std::string& key, std::string& value) {
    const auto pos = line.find(':');
    if (pos == std::string::npos || pos == 0) return false;
    key = trim_copy(line.substr(0, pos));
    value = trim_copy(line.substr(pos + 1));
    return !key.empty();
}

std::vector<std::string> parse_tag_list(std::string value) {
    value = trim_copy(std::move(value));
    std::vector<std::string> tags;
    if (value.empty()) return tags;

    if (value.front() == '[' && value.back() == ']') {
        value = value.substr(1, value.size() - 2);
    }

    std::stringstream ss(value);
    std::string item;
    while (std::getline(ss, item, ',')) {
        item = unquote_copy(item);
        if (!item.empty()) tags.push_back(item);
    }
    return tags;
}

int parse_int_or_default(const std::string& value, int default_value) {
    try {
        return std::stoi(value);
    } catch (...) {
        return default_value;
    }
}

std::string join_strings(const std::vector<std::string>& values, std::string_view delimiter) {
    std::string out;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index > 0) out += delimiter;
        out += values[index];
    }
    return out;
}

void assign_condition_field(ExternalCondition& cond, const std::string& key, const std::string& raw_value) {
    const std::string value = unquote_copy(raw_value);
    if (key == "path") cond.path = value;
    else if (key == "op") cond.op = detail::to_lower_ascii(value);
    else if (key == "value") cond.value = value;
}

bool condition_complete(const ExternalCondition& cond) {
    return !cond.path.empty() && !cond.op.empty();
}

std::optional<std::string> resolve_template_value(const std::string& token, const ExternalRuleSpec& spec, const ParsedEvent& ev, const std::string& group_key, std::size_t current_hits);

std::string render_summary_template(std::string template_text, const ExternalRuleSpec& spec, const ParsedEvent& ev, const std::string& group_key, std::size_t current_hits) {
    if (template_text.empty()) return {};

    static const std::regex placeholder_re(R"(\{\{\s*([^{}]+?)\s*\}\})");
    std::string rendered;
    rendered.reserve(template_text.size() + 32);

    std::size_t last = 0;
    for (std::sregex_iterator it(template_text.begin(), template_text.end(), placeholder_re), end;
         it != end;
         ++it) {
        const auto& match = *it;
        rendered.append(template_text, last, static_cast<std::size_t>(match.position()) - last);

        const std::string key = trim_copy(match[1].str());
        const auto value = resolve_template_value(key, spec, ev, group_key, current_hits);
        rendered += value.has_value() ? *value : "<missing>";

        last = static_cast<std::size_t>(match.position() + match.length());
    }

    rendered.append(template_text, last, std::string::npos);
    return trim_copy(rendered);
}

std::string normalize_sigma_op(std::string op) {
    op = detail::to_lower_ascii(trim_copy(std::move(op)));
    if (op == "contains") return "contains";
    if (op == "startswith" || op == "startswith") return "starts_with";
    if (op == "endswith") return "ends_with";
    if (op == "re" || op == "regex" || op == "regexp") return "regex";
    return "equals";
}

std::optional<ExternalRuleSpec> parse_external_rule_file(const std::filesystem::path& file_path) {
    std::ifstream in(file_path);
    if (!in.is_open()) {
        spdlog::warn("RuleEngine: cannot read external rule file {}", file_path.string());
        return std::nullopt;
    }

    enum class ParseState {
        Top,
        Tags,
        GroupBy,
        Conditions,
    };

    ExternalRuleSpec spec;
    ParseState state = ParseState::Top;
    ExternalCondition current_condition;
    bool has_current_condition = false;

    auto flush_current_condition = [&]() {
        if (has_current_condition && condition_complete(current_condition)) {
            if (current_condition.op == "equals" || current_condition.op == "contains" ||
                current_condition.op == "starts_with" || current_condition.op == "ends_with" ||
                current_condition.op == "regex") {
                spec.conditions.push_back(current_condition);
            }
        }
        current_condition = ExternalCondition{};
        has_current_condition = false;
    };

    std::string line;
    while (std::getline(in, line)) {
        const auto comment_pos = line.find('#');
        if (comment_pos != std::string::npos) {
            line = line.substr(0, comment_pos);
        }
        std::string trimmed = trim_copy(line);
        if (trimmed.empty()) continue;

        if (state == ParseState::Tags) {
            if (trimmed.rfind("- ", 0) == 0) {
                const std::string tag = unquote_copy(trimmed.substr(2));
                if (!tag.empty()) spec.tags.push_back(tag);
                continue;
            }
            state = ParseState::Top;
        }

        if (state == ParseState::GroupBy) {
            if (trimmed.rfind("- ", 0) == 0) {
                const std::string field = unquote_copy(trimmed.substr(2));
                if (!field.empty()) spec.group_by.push_back(field);
                continue;
            }
            state = ParseState::Top;
        }

        if (state == ParseState::Conditions) {
            if (trimmed.rfind("- ", 0) == 0) {
                flush_current_condition();
                has_current_condition = true;
                const std::string inline_part = trim_copy(trimmed.substr(2));
                if (!inline_part.empty()) {
                    std::string key;
                    std::string value;
                    if (parse_key_value(inline_part, key, value)) {
                        assign_condition_field(current_condition, key, value);
                    }
                }
                continue;
            }

            std::string key;
            std::string value;
            if (parse_key_value(trimmed, key, value) && (key == "path" || key == "op" || key == "value")) {
                has_current_condition = true;
                assign_condition_field(current_condition, key, value);
                continue;
            }

            flush_current_condition();
            state = ParseState::Top;
        }

        std::string key;
        std::string value;
        if (!parse_key_value(trimmed, key, value)) {
            continue;
        }

        if (key == "id") spec.id = unquote_copy(value);
        else if (key == "name") spec.name = unquote_copy(value);
        else if (key == "event_type") spec.event_type = unquote_copy(value);
        else if (key == "severity") spec.severity = severity_from_string(detail::to_lower_ascii(unquote_copy(value)));
        else if (key == "risk_score") {
            try {
                spec.risk_score = static_cast<uint32_t>(std::max(1, std::stoi(value)));
            } catch (...) {
                spec.risk_score = 60;
            }
        } else if (key == "min_hits") {
            spec.min_hits = std::max(1, parse_int_or_default(value, 1));
        } else if (key == "window_seconds") {
            spec.window_seconds = std::max(0, parse_int_or_default(value, 0));
        } else if (key == "alert_cooldown_seconds") {
            spec.alert_cooldown_seconds = std::max(0, parse_int_or_default(value, 0));
        } else if (key == "group_by") {
            if (value.empty()) {
                state = ParseState::GroupBy;
            } else {
                auto fields = parse_tag_list(value);
                spec.group_by.insert(spec.group_by.end(), fields.begin(), fields.end());
            }
        } else if (key == "summary") spec.summary = unquote_copy(value);
        else if (key == "summary_template") spec.summary_template = unquote_copy(value);
        else if (key == "match") spec.match_any = (detail::to_lower_ascii(unquote_copy(value)) == "any");
        else if (key == "tags") {
            if (value.empty()) {
                state = ParseState::Tags;
            } else {
                auto tags = parse_tag_list(value);
                spec.tags.insert(spec.tags.end(), tags.begin(), tags.end());
            }
        } else if (key == "conditions") {
            state = ParseState::Conditions;
            flush_current_condition();
        }
    }

    if (state == ParseState::Conditions) {
        flush_current_condition();
    }

    if (spec.id.empty() || spec.event_type.empty() || spec.conditions.empty()) {
        auto sigma_spec = parse_sigma_style_rule_file(file_path);
        if (sigma_spec.has_value()) {
            return sigma_spec;
        }
        spdlog::warn("RuleEngine: skip invalid external rule file {} (missing id/event_type/conditions)",
                     file_path.string());
        return std::nullopt;
    }

    if (spec.name.empty()) spec.name = spec.id;
    if (spec.summary.empty()) spec.summary = "External rule matched: " + spec.name;
    if (spec.tags.empty()) spec.tags = {"external", "yaml"};
    if (spec.min_hits > 1) {
        if (spec.window_seconds <= 0) spec.window_seconds = 300;
        if (spec.alert_cooldown_seconds <= 0) spec.alert_cooldown_seconds = spec.window_seconds;
    }

    return spec;
}

std::optional<ExternalRuleSpec> parse_sigma_style_rule_file(const std::filesystem::path& file_path) {
    std::ifstream in(file_path);
    if (!in.is_open()) return std::nullopt;

    ExternalRuleSpec spec;
    std::unordered_map<std::string, std::vector<ExternalCondition>> selections;
    std::string condition_expr;
    std::string current_selection;
    std::optional<ExternalCondition> pending_list_condition;

    bool in_detection = false;
    bool in_tags = false;
    int detection_indent = -1;
    int selection_indent = -1;

    auto leading_spaces = [](const std::string& s) {
        int count = 0;
        while (count < static_cast<int>(s.size()) && s[static_cast<std::size_t>(count)] == ' ') {
            ++count;
        }
        return count;
    };

    auto append_selection_condition = [&](const std::string& sel,
                                          ExternalCondition cond) {
        if (sel.empty()) return;
        if (!condition_complete(cond)) return;
        selections[sel].push_back(std::move(cond));
    };

    std::string raw_line;
    while (std::getline(in, raw_line)) {
        const auto comment_pos = raw_line.find('#');
        if (comment_pos != std::string::npos) {
            raw_line = raw_line.substr(0, comment_pos);
        }

        if (trim_copy(raw_line).empty()) continue;

        const int indent = leading_spaces(raw_line);
        const std::string trimmed = trim_copy(raw_line);

        if (in_tags) {
            if (indent > 0 && trimmed.rfind("- ", 0) == 0) {
                const std::string tag = unquote_copy(trimmed.substr(2));
                if (!tag.empty()) spec.tags.push_back(tag);
                continue;
            }
            in_tags = false;
        }

        if (in_detection) {
            if (indent <= detection_indent) {
                in_detection = false;
                current_selection.clear();
                pending_list_condition.reset();
            } else {
                if (!current_selection.empty() && pending_list_condition.has_value()) {
                    if (indent > selection_indent && trimmed.rfind("- ", 0) == 0) {
                        auto cond = *pending_list_condition;
                        cond.value = unquote_copy(trimmed.substr(2));
                        append_selection_condition(current_selection, std::move(cond));
                        continue;
                    }
                    pending_list_condition.reset();
                }

                if (indent == detection_indent + 2) {
                    std::string key;
                    std::string value;
                    if (parse_key_value(trimmed, key, value)) {
                        if (key == "condition") {
                            condition_expr = unquote_copy(value);
                            current_selection.clear();
                            continue;
                        }

                        current_selection = key;
                        selection_indent = indent;
                        if (!value.empty()) {
                            current_selection.clear();
                        }
                        continue;
                    }
                }

                if (!current_selection.empty() && indent > selection_indent) {
                    std::string key;
                    std::string value;
                    if (parse_key_value(trimmed, key, value)) {
                        std::string path = key;
                        std::string op = "equals";
                        const auto pipe_pos = key.find('|');
                        if (pipe_pos != std::string::npos) {
                            path = trim_copy(key.substr(0, pipe_pos));
                            op = normalize_sigma_op(key.substr(pipe_pos + 1));
                        }

                        ExternalCondition cond;
                        cond.path = path;
                        cond.op = op;

                        if (value.empty()) {
                            pending_list_condition = cond;
                        } else {
                            cond.value = unquote_copy(value);
                            append_selection_condition(current_selection, std::move(cond));
                        }
                        continue;
                    }
                }
                continue;
            }
        }

        std::string key;
        std::string value;
        if (!parse_key_value(trimmed, key, value)) continue;

        if (key == "detection") {
            in_detection = true;
            detection_indent = indent;
            current_selection.clear();
            pending_list_condition.reset();
            continue;
        }

        if (key == "id") spec.id = unquote_copy(value);
        else if (key == "name" || key == "title") spec.name = unquote_copy(value);
        else if (key == "description") spec.summary = unquote_copy(value);
        else if (key == "summary_template") spec.summary_template = unquote_copy(value);
        else if (key == "severity" || key == "level") spec.severity = severity_from_string(detail::to_lower_ascii(unquote_copy(value)));
        else if (key == "risk_score") {
            try {
                spec.risk_score = static_cast<uint32_t>(std::max(1, std::stoi(value)));
            } catch (...) {
                spec.risk_score = 60;
            }
        } else if (key == "tags") {
            if (value.empty()) {
                in_tags = true;
            } else {
                auto tags = parse_tag_list(value);
                spec.tags.insert(spec.tags.end(), tags.begin(), tags.end());
            }
        }
    }

    if (spec.id.empty() || selections.empty()) {
        return std::nullopt;
    }

    if (spec.name.empty()) spec.name = spec.id;
    if (spec.summary.empty()) spec.summary = "External Sigma-like rule matched: " + spec.name;
    if (spec.tags.empty()) spec.tags = {"external", "sigma-like"};

    auto extract_event_type_from_conditions = [&](std::vector<ExternalCondition>& conditions) {
        for (auto it = conditions.begin(); it != conditions.end();) {
            const bool event_type_path =
                (it->path == "event_type" || it->path == "event.event_type");
            if (event_type_path && (it->op == "equals" || it->op == "contains")) {
                spec.event_type = detail::to_lower_ascii(it->value);
                it = conditions.erase(it);
            } else {
                ++it;
            }
        }
    };

    auto append_selection = [&](const std::string& selection_name,
                                std::vector<ExternalCondition>& out) {
        const auto it = selections.find(selection_name);
        if (it == selections.end()) return false;
        out.insert(out.end(), it->second.begin(), it->second.end());
        return true;
    };

    std::vector<ExternalCondition> compiled;
    std::string cond = detail::to_lower_ascii(trim_copy(condition_expr));

    if (cond.empty() && selections.count("selection") > 0) {
        cond = "selection";
    }

    if (cond == "all of selection*" || cond == "all of them") {
        spec.match_any = false;
        for (auto& entry : selections) {
            compiled.insert(compiled.end(), entry.second.begin(), entry.second.end());
        }
    } else if (cond == "1 of selection*" || cond == "any of them") {
        spec.match_any = true;
        for (auto& entry : selections) {
            compiled.insert(compiled.end(), entry.second.begin(), entry.second.end());
        }
    } else {
        std::smatch m;
        const std::regex and_re(R"(^([a-z0-9_-]+)\s+and\s+([a-z0-9_-]+)$)");
        const std::regex or_re(R"(^([a-z0-9_-]+)\s+or\s+([a-z0-9_-]+)$)");
        if (std::regex_match(cond, m, and_re)) {
            spec.match_any = false;
            append_selection(m[1].str(), compiled);
            append_selection(m[2].str(), compiled);
        } else if (std::regex_match(cond, m, or_re)) {
            spec.match_any = true;
            append_selection(m[1].str(), compiled);
            append_selection(m[2].str(), compiled);
        } else {
            if (!append_selection(cond, compiled) && !cond.empty()) {
                append_selection(condition_expr, compiled);
            }
        }
    }

    if (compiled.empty()) {
        return std::nullopt;
    }

    extract_event_type_from_conditions(compiled);
    if (spec.event_type.empty()) {
        return std::nullopt;
    }

    if (compiled.empty()) {
        return std::nullopt;
    }

    spec.conditions = std::move(compiled);
    return spec;
}

std::optional<std::string> json_node_to_string(const nlohmann::json& node) {
    if (node.is_null()) return std::nullopt;
    if (node.is_string()) return node.get<std::string>();
    if (node.is_boolean()) return node.get<bool>() ? "true" : "false";
    if (node.is_number_integer()) return std::to_string(node.get<long long>());
    if (node.is_number_unsigned()) return std::to_string(node.get<unsigned long long>());
    if (node.is_number_float()) return std::to_string(node.get<double>());
    return node.dump();
}

const nlohmann::json* find_json_path(const nlohmann::json& root,
                                     const std::string& dotted_path) {
    const nlohmann::json* cur = &root;
    std::stringstream ss(dotted_path);
    std::string token;
    while (std::getline(ss, token, '.')) {
        token = trim_copy(token);
        if (token.empty()) return nullptr;
        if (!cur->is_object() || !cur->contains(token)) return nullptr;
        cur = &cur->at(token);
    }
    return cur;
}

std::optional<std::string> resolve_field_value(const ParsedEvent& ev,
                                               const std::string& path) {
    if (path.empty()) return std::nullopt;

    if (path == "schema_version") return ev.schema_version;
    if (path == "event_id") return ev.event_id;
    if (path == "ts") return ev.ts;
    if (path == "event_type") return ev.event_type;
    if (path == "host") return ev.host;
    if (path == "agent_id") return ev.agent_id;
    if (path == "source") return ev.source;
    if (path == "tenant_id") return ev.tenant_id;
    if (path == "trace_id") return ev.trace_id;
    if (path == "process_guid") return ev.process_guid;
    if (path == "user_name") return ev.user_name;
    if (path == "src_ip") return ev.src_ip;
    if (path == "dst_ip") return ev.dst_ip;
    if (path == "dst_port") return std::to_string(ev.dst_port);
    if (path == "severity") return severity_to_string(ev.severity);

    if (path.rfind("event.", 0) == 0) {
        if (!ev.doc.contains("event")) return std::nullopt;
        const auto* node = find_json_path(ev.doc.at("event"), path.substr(6));
        if (!node) return std::nullopt;
        return json_node_to_string(*node);
    }

    if (path.rfind("doc.", 0) == 0) {
        const auto* node = find_json_path(ev.doc, path.substr(4));
        if (!node) return std::nullopt;
        return json_node_to_string(*node);
    }

    const auto* node = find_json_path(ev.doc, path);
    if (!node) return std::nullopt;
    return json_node_to_string(*node);
}

std::optional<std::string> resolve_template_value(const std::string& token, const ExternalRuleSpec& spec, const ParsedEvent& ev, const std::string& group_key, std::size_t current_hits) {
    if (token == "group_key" || token == "match.group_key") {
        if (!group_key.empty()) return group_key;
        return std::nullopt;
    }
    if (token == "current_hits" || token == "match.current_hits") {
        return std::to_string(current_hits);
    }
    if (token == "min_hits" || token == "rule.min_hits") {
        return std::to_string(spec.min_hits);
    }
    if (token == "window_seconds" || token == "rule.window_seconds") {
        return std::to_string(spec.window_seconds);
    }
    if (token == "alert_cooldown_seconds" || token == "rule.alert_cooldown_seconds") {
        return std::to_string(spec.alert_cooldown_seconds);
    }
    if (token == "rule.id") return spec.id;
    if (token == "rule.name") return spec.name;
    if (token == "rule.event_type") return spec.event_type;
    if (token == "rule.severity") return severity_to_string(spec.severity);
    if (token == "rule.risk_score") return std::to_string(spec.risk_score);
    if (token == "rule.tags") return join_strings(spec.tags, ",");
    if (token == "rule.summary") return spec.summary;
    return resolve_field_value(ev, token);
}

bool evaluate_condition(const ExternalCondition& condition, const ParsedEvent& ev) {
    const auto actual = resolve_field_value(ev, condition.path);
    if (!actual.has_value()) return false;

    const std::string actual_value = *actual;
    const std::string expected_value = condition.value;

    if (condition.op == "equals") {
        return detail::to_lower_ascii(actual_value) == detail::to_lower_ascii(expected_value);
    }
    if (condition.op == "contains") {
        return detail::contains_ci(actual_value, expected_value);
    }
    if (condition.op == "starts_with") {
        const std::string act = detail::to_lower_ascii(actual_value);
        const std::string exp = detail::to_lower_ascii(expected_value);
        return act.rfind(exp, 0) == 0;
    }
    if (condition.op == "ends_with") {
        return detail::ends_with_ci(actual_value, expected_value);
    }
    if (condition.op == "regex") {
        try {
            return std::regex_search(actual_value, std::regex(expected_value, std::regex_constants::icase));
        } catch (...) {
            return false;
        }
    }
    return false;
}

class ExternalYamlRule final : public BaseRule {
public:
    explicit ExternalYamlRule(ExternalRuleSpec spec) : spec_(std::move(spec)) {}

    std::string_view id() const noexcept override { return spec_.id; }
    std::string_view name() const noexcept override { return spec_.name; }
    Severity severity() const noexcept override { return spec_.severity; }
    uint32_t risk_score() const noexcept override { return spec_.risk_score; }
    std::vector<std::string> tags() const override { return spec_.tags; }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != spec_.event_type) return std::nullopt;

        bool matched = spec_.match_any ? false : true;
        std::vector<nlohmann::json> evidence;
        for (const auto& condition : spec_.conditions) {
            const bool ok = evaluate_condition(condition, ev);
            if (ok) {
                nlohmann::json c;
                c["path"] = condition.path;
                c["op"] = condition.op;
                c["value"] = condition.value;
                evidence.push_back(std::move(c));
            }

            if (spec_.match_any) {
                matched = matched || ok;
            } else {
                matched = matched && ok;
            }
        }

        if (!matched) return std::nullopt;

        const auto gate = should_emit(ev);
        if (!gate.emit) return std::nullopt;

        nlohmann::json ctx;
        ctx["source"] = "external_yaml";
        ctx["event_type"] = spec_.event_type;
        ctx["match_mode"] = spec_.match_any ? "any" : "all";
        ctx["matched_conditions"] = evidence;
        if (!gate.group_key.empty()) ctx["group_key"] = gate.group_key;
        if (spec_.min_hits > 1) {
            ctx["min_hits"] = spec_.min_hits;
            ctx["current_hits"] = gate.current_hits;
            ctx["window_seconds"] = spec_.window_seconds;
            ctx["alert_cooldown_seconds"] = spec_.alert_cooldown_seconds;
            ctx["group_by"] = spec_.group_by;
        }

        std::string summary = spec_.summary;
        if (!spec_.summary_template.empty()) {
            summary = render_summary_template(spec_.summary_template,
                                              spec_,
                                              ev,
                                              gate.group_key,
                                              gate.current_hits);
        }
        return make_match(ev, std::move(summary), ctx);
    }

private:
    struct EmitDecision {
        bool emit{false};
        std::string group_key;
        std::size_t current_hits{0};
    };

    struct Bucket {
        std::deque<std::chrono::system_clock::time_point> hits;
        std::chrono::system_clock::time_point last_alert{};
    };

    std::string build_group_key(const ParsedEvent& ev) const {
        if (!spec_.group_by.empty()) {
            std::string key;
            for (const auto& field : spec_.group_by) {
                const auto value = resolve_field_value(ev, field);
                if (!key.empty()) key += "|";
                key += field + "=" + (value.has_value() ? *value : "<missing>");
            }
            return key;
        }
        return ev.tenant_id + "|" + ev.host + "|" + ev.event_type + "|" + spec_.id;
    }

    void cleanup_locked(std::chrono::system_clock::time_point now) const {
        const int ttl_seconds = std::max(
            spec_.window_seconds,
            std::max(spec_.alert_cooldown_seconds, 300));
        const auto ttl = std::chrono::seconds(ttl_seconds);

        for (auto it = buckets_.begin(); it != buckets_.end();) {
            while (!it->second.hits.empty() && (now - it->second.hits.front()) > ttl) {
                it->second.hits.pop_front();
            }

            const bool stale_last_alert =
                it->second.last_alert.time_since_epoch().count() != 0 &&
                (now - it->second.last_alert) > ttl;
            if (stale_last_alert) {
                it->second.last_alert = std::chrono::system_clock::time_point{};
            }

            const bool empty_bucket = it->second.hits.empty() &&
                                      it->second.last_alert.time_since_epoch().count() == 0;
            if (empty_bucket) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

    EmitDecision should_emit(const ParsedEvent& ev) const {
        if (spec_.min_hits <= 1 && spec_.alert_cooldown_seconds <= 0) {
            return EmitDecision{true, "", 1};
        }

        const auto now = std::chrono::system_clock::now();
        const std::string group_key = build_group_key(ev);

        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_locked(now);

        auto& bucket = buckets_[group_key];

        const int window_seconds = std::max(1, spec_.window_seconds > 0 ? spec_.window_seconds : 300);
        const auto window = std::chrono::seconds(window_seconds);
        while (!bucket.hits.empty() && (now - bucket.hits.front()) > window) {
            bucket.hits.pop_front();
        }
        bucket.hits.push_back(now);

        if (bucket.hits.size() < static_cast<std::size_t>(std::max(1, spec_.min_hits))) {
            return EmitDecision{false, group_key, bucket.hits.size()};
        }

        const int cooldown_seconds = std::max(0, spec_.alert_cooldown_seconds);
        if (cooldown_seconds > 0 && bucket.last_alert.time_since_epoch().count() != 0) {
            const auto cooldown = std::chrono::seconds(cooldown_seconds);
            if ((now - bucket.last_alert) < cooldown) {
                return EmitDecision{false, group_key, bucket.hits.size()};
            }
        }

        bucket.last_alert = now;
        return EmitDecision{true, group_key, bucket.hits.size()};
    }

    ExternalRuleSpec spec_;
    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

}

RuleEngine::RuleEngine() {
    rules_.push_back(std::make_unique<RansomwareShadowCopyDeleteRule>());
    rules_.push_back(std::make_unique<CorrelatedAuthProcessRarePortRule>());
    rules_.push_back(std::make_unique<CorrelatedAuthToSensitiveFileRule>());
    rules_.push_back(std::make_unique<SensitiveFileAccessRule>());
    rules_.push_back(std::make_unique<CorrelatedExecutionToRarePortRule>());
    rules_.push_back(std::make_unique<SqlInjectionToolExecutionRule>());
    rules_.push_back(std::make_unique<SuspiciousShellRule>());
    rules_.push_back(std::make_unique<AuthPasswordSprayRule>());
    rules_.push_back(std::make_unique<AuthBruteForceRule>());
    rules_.push_back(std::make_unique<NetworkPortScanRule>());
    rules_.push_back(std::make_unique<PhishingFrameworkExecutionRule>());
    rules_.push_back(std::make_unique<NetworkC2BeaconRule>());
    rules_.push_back(std::make_unique<NetworkDdosFloodRule>());
    rules_.push_back(std::make_unique<SuspiciousTempFileDropRule>());
    rules_.push_back(std::make_unique<NetworkRarePortRule>());

    spdlog::info("RuleEngine: loaded {} built-in rules", rules_.size());
    for (const auto& r : rules_) {
        spdlog::debug("  rule id={} name=\"{}\" severity={} risk={}", r->id(), r->name(), severity_to_string(r->severity()), r->risk_score());
    }
}

void RuleEngine::add_rule(std::unique_ptr<BaseRule> rule) {
    spdlog::info("RuleEngine: added rule id={}", rule->id());
    rules_.push_back(std::move(rule));
}

std::size_t RuleEngine::load_external_rules_from_dir(const std::string& dir_path) {
    if (dir_path.empty()) return 0;

    std::error_code ec;
    std::filesystem::path root(dir_path);
    if (!root.is_absolute()) {
        const auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            std::filesystem::path cursor = cwd;
            bool resolved = false;
            for (int depth = 0; depth <= 6; ++depth) {
                const auto candidate = cursor / root;
                if (std::filesystem::exists(candidate, ec) && std::filesystem::is_directory(candidate, ec)) {
                    root = candidate;
                    resolved = true;
                    break;
                }
                if (!cursor.has_parent_path()) break;
                cursor = cursor.parent_path();
            }
            if (!resolved) {
                root = cwd / root;
            }
        }
    }

    if (!std::filesystem::exists(root, ec) || !std::filesystem::is_directory(root, ec)) {
        spdlog::warn("RuleEngine: external rules dir not found: {}", dir_path);
        return 0;
    }

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (ec) break;
        if (!entry.is_regular_file()) continue;
        const std::string ext = detail::to_lower_ascii(entry.path().extension().string());
        if (ext == ".yml" || ext == ".yaml") {
            files.push_back(entry.path());
        }
    }

    std::sort(files.begin(), files.end());

    std::size_t loaded = 0;
    for (const auto& file : files) {
        auto spec = parse_external_rule_file(file);
        if (!spec.has_value()) continue;

        add_rule(std::make_unique<ExternalYamlRule>(std::move(*spec)));
        ++loaded;
    }

    spdlog::info("RuleEngine: loaded {} external YAML rules from {}", loaded, root.string());
    return loaded;
}

std::vector<RuleMatch> RuleEngine::evaluate(const ParsedEvent& event) const {
    std::vector<RuleMatch> matches;
    for (const auto& rule : rules_) {
        try {
            auto match = rule->evaluate(event);
            if (match.has_value()) {
                spdlog::info("RuleEngine: MATCH rule={} host={} event_id={} risk={}",
                             match->rule_id, match->host, match->event_id, match->risk_score);
                matches.push_back(std::move(match.value()));
            }
        } catch (const std::exception& ex) {
            spdlog::error("RuleEngine: rule {} evaluation error: {}", rule->id(), ex.what());
        }
    }
    return matches;
}

std::vector<RuleMatch> RuleEngine::evaluate_batch(const std::vector<ParsedEvent>& events) const {
    std::vector<RuleMatch> all_matches;
    for (const auto& ev : events) {
        auto matches = evaluate(ev);
        all_matches.insert(all_matches.end(), std::make_move_iterator(matches.begin()), std::make_move_iterator(matches.end()));
    }
    return all_matches;
}

}
