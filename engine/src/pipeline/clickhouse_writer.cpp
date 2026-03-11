// engine/src/pipeline/clickhouse_writer.cpp
#include "pipeline/clickhouse_writer.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace aegis::pipeline {

using json = nlohmann::json;

ClickHouseWriter::ClickHouseWriter(const Config& cfg) : cfg_(cfg) {
    spdlog::info("ClickHouseWriter: target={}:{} db={}",
                 cfg_.clickhouse_host, cfg_.clickhouse_port, cfg_.clickhouse_db);
}

// ---------------------------------------------------------------------------
// Timestamp conversion
// ---------------------------------------------------------------------------

std::string ClickHouseWriter::to_ch_datetime(const std::string& rfc3339) {
    // Fast path: take first 19 chars "2026-03-10T12:00:00" and replace T with space.
    if (rfc3339.size() < 19) return "1970-01-01 00:00:00";
    std::string out = rfc3339.substr(0, 19);
    if (out[10] == 'T') out[10] = ' ';
    return out;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

bool ClickHouseWriter::http_insert(const std::string& table, const std::string& body) {
    const int max_attempts = std::max(1, cfg_.engine_retry_max_attempts);
    const int base_delay_ms = std::max(1, cfg_.engine_retry_base_delay_ms);

    // Build query string: INSERT INTO <db>.<table> FORMAT JSONEachRow
    std::string query = "INSERT INTO " + cfg_.clickhouse_db + "." + table +
                        " FORMAT JSONEachRow";

    std::string encoded_query;
    for (char c : query) {
        if (c == ' ')       encoded_query += "%20";
        else if (c == '+')  encoded_query += "%2B";
        else                encoded_query += c;
    }

    std::string path = "/?query=" + encoded_query;
    if (!cfg_.clickhouse_user.empty()) {
        path += "&user=" + cfg_.clickhouse_user;
    }
    if (!cfg_.clickhouse_password.empty()) {
        path += "&password=" + cfg_.clickhouse_password;
    }

    for (int attempt = 1; attempt <= max_attempts; ++attempt) {
        httplib::Client cli(cfg_.clickhouse_host, static_cast<int>(cfg_.clickhouse_port));
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(30, 0);

        auto res = cli.Post(path, body, "application/json");
        if (res && res->status == 200) {
            return true;
        }

        if (!res) {
            spdlog::warn("ClickHouseWriter: HTTP POST failed attempt {}/{} table={}",
                         attempt, max_attempts, table);
        } else {
            spdlog::warn("ClickHouseWriter: INSERT {} failed attempt {}/{} status={} body={}",
                         table,
                         attempt,
                         max_attempts,
                         res->status,
                         res->body.substr(0, 512));
        }

        if (attempt < max_attempts) {
            const int delay_ms = std::min(base_delay_ms * (1 << std::min(attempt - 1, 4)), 5000);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
    }

    spdlog::error("ClickHouseWriter: exhausted retries for table={}", table);
    return false;
}

// ---------------------------------------------------------------------------
// write_raw_events
// ---------------------------------------------------------------------------

bool ClickHouseWriter::write_raw_events(const std::vector<ParsedEvent>& events) {
    if (events.empty()) return true;

    // Build newline-delimited JSONEachRow body.
    // Columns: ts, host, source, event_type, process_guid, src_ip, dst_ip, dst_port,
    //          user_name, event_json
    std::string body;
    body.reserve(events.size() * 512);

    for (const auto& ev : events) {
        json row;
        row["ts"]           = to_ch_datetime(ev.ts);
        row["host"]         = ev.host;
        row["source"]       = ev.source;
        row["event_type"]   = ev.event_type;
        row["process_guid"] = ev.process_guid;
        row["src_ip"]       = ev.src_ip;
        row["dst_ip"]       = ev.dst_ip;
        row["dst_port"]     = ev.dst_port;
        row["user_name"]    = ev.user_name;
        row["event_json"]   = ev.raw_json;
        body += row.dump() + "\n";
    }

    bool ok = http_insert("raw_events", body);
    if (ok) {
        spdlog::debug("ClickHouseWriter: inserted {} rows to raw_events", events.size());
    }
    return ok;
}

// ---------------------------------------------------------------------------
// write_alert
// ---------------------------------------------------------------------------

bool ClickHouseWriter::write_alert(const RuleMatch& match) {
    // Columns: ts, rule_id, severity, risk_score, host, process_guid, summary, context_json
    json row;
    row["ts"]           = to_ch_datetime(match.event_ts);
    row["rule_id"]      = match.rule_id;
    row["severity"]     = severity_to_string(match.severity);
    row["risk_score"]   = static_cast<uint8_t>(std::min(match.risk_score, 255u));
    row["host"]         = match.host;
    row["process_guid"] = match.process_guid;
    row["summary"]      = match.summary;
    row["context_json"] = match.context.dump();

    bool ok = http_insert("alerts", row.dump() + "\n");
    if (ok) {
        spdlog::debug("ClickHouseWriter: alert inserted rule={} host={}", match.rule_id, match.host);
    }
    return ok;
}

}  // namespace aegis::pipeline
