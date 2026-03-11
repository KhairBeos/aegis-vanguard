#pragma once
// engine/src/pipeline/clickhouse_writer.hpp
// Writes batches of ParsedEvents to aegis.raw_events and alerts to aegis.alerts
// via the ClickHouse HTTP API (port 8123) using JSONEachRow format.

#include <string>
#include <vector>

#include "config.hpp"
#include "types.hpp"

namespace aegis::pipeline {

class ClickHouseWriter {
public:
    explicit ClickHouseWriter(const Config& cfg);

    // Insert a batch of validated events into aegis.raw_events.
    // Logs an error and returns false on failure (non-throwing for pipeline resilience).
    bool write_raw_events(const std::vector<ParsedEvent>& events);

    // Insert a single alert into aegis.alerts.
    bool write_alert(const RuleMatch& match);

private:
    Config cfg_;

    // Execute an INSERT query via HTTP POST to ClickHouse.
    // query_suffix: the part after "INSERT INTO ...FORMAT JSONEachRow"
    // body: newline-delimited JSON rows
    bool http_insert(const std::string& table, const std::string& body);

    // Convert RFC3339 timestamp to ClickHouse DateTime string.
    // Input:  "2026-03-10T12:00:00Z"
    // Output: "2026-03-10 12:00:00"
    static std::string to_ch_datetime(const std::string& rfc3339);
};

}  // namespace aegis::pipeline
