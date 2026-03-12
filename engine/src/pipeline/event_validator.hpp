#pragma once
// Parses raw JSON from Kafka, validates against api_spec v1.1 contract, and extracts hot columns into a ParsedEvent struct
// Returns either a valid ParsedEvent or a ValidationFail describing why it failed

#include <string>
#include <variant>

#include "types.hpp"

namespace aegis::pipeline {

class EventValidator {
public:
    EventValidator() = default;

    // Validate a raw JSON string from Kafka
    // Returns ParsedEvent on success, ValidationFail on any structural error
    ValidationResult validate(const std::string& raw_json) const;

private:
    void extract_hot_columns(ParsedEvent& ev,
                             const nlohmann::json& event_payload) const;
};

}
