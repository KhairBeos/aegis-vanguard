#pragma once
// engine/include/types.hpp — Shared data structures used across all engine components.

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

namespace aegis {

// Severity
enum class Severity : uint8_t {
    Info     = 1,
    Low      = 2,
    Medium   = 3,
    High     = 4,
    Critical = 5,
};

inline Severity severity_from_string(std::string_view s) noexcept {
    if (s == "low")      return Severity::Low;
    if (s == "medium")   return Severity::Medium;
    if (s == "high")     return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

inline std::string severity_to_string(Severity sev) noexcept {
    switch (sev) {
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
        default:                 return "info";
    }
}

inline uint32_t default_risk_score(Severity sev) noexcept {
    switch (sev) {
        case Severity::Low:      return 25;
        case Severity::Medium:   return 50;
        case Severity::High:     return 75;
        case Severity::Critical: return 90;
        default:                 return 10;
    }
}

// KafkaMessage — raw message received from Kafka
struct KafkaMessage {
    std::string payload;
    std::string topic;
    int32_t     partition{0};
    int64_t     offset{0};
};

// ParsedEvent — validated, normalized event extracted from a KafkaMessage
struct ParsedEvent {
    // Envelope fields (api_spec v1.1)
    std::string schema_version;
    std::string event_id;
    std::string ts;
    std::string host;
    std::string agent_id;
    std::string source;
    std::string event_type; // process_start | network_connect | file_open | auth_failure
    Severity    severity{Severity::Info};
    std::string tenant_id;
    std::string trace_id;
    std::string process_guid;

    // Hot columns extracted for direct ClickHouse column storage
    std::string src_ip;
    std::string dst_ip;
    uint16_t    dst_port{0};
    std::string user_name;

    // Full original JSON string
    std::string raw_json;

    // Parsed JSON for rule evaluation
    nlohmann::json doc;
};

// ValidationError
enum class ValidationError {
    ParseFailed,
    MissingRequiredField,
    InvalidFieldType,
    SchemaVersionMismatch,
};

struct ValidationFail {
    ValidationError code;
    std::string     detail;
};

using ValidationResult = std::variant<ParsedEvent, ValidationFail>;

// DlqEntry — a failed message forwarded to the dead-letter topic
struct DlqEntry {
    std::string raw_message; // original Kafka payload
    std::string error_reason;
    std::string source_topic;
    int32_t     partition{0};
    int64_t     offset{0};
    std::string ts; // ISO8601 timestamp when DLQ entry was created
};

// RuleMatch — result of a rule evaluation against a ParsedEvent
struct RuleMatch {
    std::string rule_id;
    std::string rule_name;
    Severity    severity{Severity::Medium};
    uint32_t    risk_score{50};
    std::string summary;
    nlohmann::json context; // structured evidence fields
    std::vector<std::string> tags;

    // Back-reference to the triggering event
    std::string event_id;
    std::string host;
    std::string tenant_id;
    std::string event_ts;
    std::string process_guid;
};

}
