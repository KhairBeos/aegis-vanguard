#include "pipeline/event_validator.hpp"

#include <spdlog/spdlog.h>

#include <array>
#include <string_view>

namespace aegis::pipeline {

using json = nlohmann::json;

// Required top-level fields per api_spec v1.1
static constexpr std::array REQUIRED_FIELDS{
    "schema_version", "event_id", "ts", "host",
    "agent_id",       "source",   "event_type",
    "severity",       "tenant_id","event"};

static constexpr std::string_view SUPPORTED_SCHEMA = "v1.1";

ValidationResult EventValidator::validate(const std::string& raw_json) const {
    json doc;
    try {
        doc = json::parse(raw_json);
    } catch (const json::exception& ex) {
        return ValidationFail{ValidationError::ParseFailed, std::string("JSON parse: ") + ex.what()};
    }

    if (!doc.is_object()) {
        return ValidationFail{ValidationError::ParseFailed, "root must be a JSON object"};
    }

    // Required field presence check
    for (const auto* field : REQUIRED_FIELDS) {
        if (!doc.contains(field)) {
            return ValidationFail{ValidationError::MissingRequiredField, std::string("missing field: ") + field};
        }
    }

    // Schema version
    std::string schema_ver;
    try {
        schema_ver = doc.at("schema_version").get<std::string>();
    } catch (...) {
        return ValidationFail{ValidationError::InvalidFieldType, "schema_version must be string"};
    }
    if (schema_ver != SUPPORTED_SCHEMA) {
        return ValidationFail{ValidationError::SchemaVersionMismatch, std::string("unsupported schema_version: ") + schema_ver};
    }

    // Build ParsedEvent
    ParsedEvent ev;
    try {
        ev.schema_version = schema_ver;
        ev.event_id       = doc.at("event_id").get<std::string>();
        ev.ts             = doc.at("ts").get<std::string>();
        ev.host           = doc.at("host").get<std::string>();
        ev.agent_id       = doc.at("agent_id").get<std::string>();
        ev.source         = doc.at("source").get<std::string>();
        ev.event_type     = doc.at("event_type").get<std::string>();
        ev.severity       = severity_from_string(doc.at("severity").get<std::string>());
        ev.tenant_id      = doc.at("tenant_id").get<std::string>();
        ev.trace_id       = doc.value("trace_id", "");
        ev.process_guid   = doc.value("process_guid", "");
    } catch (const json::exception& ex) {
        return ValidationFail{ValidationError::InvalidFieldType, std::string("field type error: ") + ex.what()};
    }

    // Minimal non-empty checks for security-sensitive identity fields
    if (ev.event_id.empty() || ev.host.empty() || ev.tenant_id.empty()) {
        return ValidationFail{ValidationError::MissingRequiredField, std::string("event_id, host, and tenant_id must be non-empty")};
    }

    ev.raw_json = raw_json;
    ev.doc      = std::move(doc);

    // Extract typed hot columns from the nested event payload
    const auto& payload = ev.doc.at("event");
    if (payload.is_object()) {
        extract_hot_columns(ev, payload);
    }

    return ev;
}

void EventValidator::extract_hot_columns(ParsedEvent& ev,
                                          const json& payload) const {
    const auto& et = ev.event_type;

    if (et == "network_connect" && payload.contains("network")) {
        const auto& n = payload.at("network");
        ev.src_ip   = n.value("src_ip", "");
        ev.dst_ip   = n.value("dst_ip", "");
        ev.dst_port = static_cast<uint16_t>(n.value<uint32_t>("dst_port", 0));
    } else if (et == "process_start" && payload.contains("process")) {
        const auto& p = payload.at("process");
        ev.user_name = p.value("user_name", "");
    } else if (et == "file_open" && payload.contains("file")) {
        const auto& f = payload.at("file");
        ev.user_name = f.value("user_name", "");

        if (ev.process_guid.empty()) {
            ev.process_guid = f.value("process_guid", "");
        }
    } else if (et == "auth_failure" && payload.contains("auth")) {
        const auto& a = payload.at("auth");
        ev.user_name = a.value("user_name", "");
        ev.src_ip    = a.value("src_ip", "");
    }
}

}
