#include "detection/alert_publisher.hpp"
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <chrono>
#include <iomanip>
#include <random>
#include <sstream>

namespace aegis::detection {

using json = nlohmann::json;

// Alert ID generator  — compact 32-hex UUID4
std::string AlertPublisher::generate_alert_id() {
    // RFC4122 UUID v4: random bits with version (4) and variant bits set.
    thread_local std::mt19937_64 rng{
        static_cast<uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count())};

    uint64_t hi = rng();
    uint64_t lo = rng();

    // Set version 4 and variant bits.
    hi = (hi & 0xFFFFFFFFFFFF0FFFull) | 0x0000000000004000ull;
    lo = (lo & 0x3FFFFFFFFFFFFFFFull) | 0x8000000000000000ull;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << hi
        << std::setw(16) << lo;
    return oss.str();
}

// Alert JSON builder
std::string AlertPublisher::build_alert_json(const RuleMatch& match) {
    json alert;
    alert["schema_version"] = "v1.1";
    alert["alert_id"]       = generate_alert_id();
    alert["ts"]             = match.event_ts;
    alert["rule_id"]        = match.rule_id;
    alert["rule_name"]      = match.rule_name;
    alert["severity"]       = severity_to_string(match.severity);
    alert["risk_score"]     = match.risk_score;
    alert["host"]           = match.host;
    alert["tenant_id"]      = match.tenant_id;
    alert["event_id"]       = match.event_id;
    alert["process_guid"]   = match.process_guid;
    alert["summary"]        = match.summary;
    alert["context"]        = match.context.is_null() ? json::object() : match.context;
    alert["tags"]           = match.tags;
    return alert.dump();
}

// AlertPublisher
AlertPublisher::AlertPublisher(const Config& cfg, std::shared_ptr<pipeline::KafkaProducer>  producer, std::shared_ptr<pipeline::ClickHouseWriter> ch_writer) : cfg_(cfg), producer_(std::move(producer)), ch_writer_(std::move(ch_writer)) {}

bool AlertPublisher::publish(const RuleMatch& match) {
    const std::string alert_json = build_alert_json(match);

    // 1. Publish to Kafka siem.alerts topic
    bool kafka_ok = true;
    try {
        kafka_ok = producer_->produce(cfg_.kafka_topic_alerts, match.host, alert_json);
        if (kafka_ok) {
            spdlog::info("AlertPublisher: rule={} host={} risk={} -> Kafka:{}",
                         match.rule_id, match.host, match.risk_score, cfg_.kafka_topic_alerts);
        }
    } catch (const std::exception& ex) {
        spdlog::error("AlertPublisher: Kafka publish failed: {}", ex.what());
        kafka_ok = false;
    }

    bool ch_ok = ch_writer_->write_alert(match);
    if (!ch_ok) {
        spdlog::error("AlertPublisher: ClickHouse write failed rule={} host={}",
                      match.rule_id, match.host);
    }

    return kafka_ok && ch_ok;
}

bool AlertPublisher::publish_batch(const std::vector<RuleMatch>& matches) {
    bool ok = true;
    for (const auto& m : matches) {
        ok = publish(m) && ok;
    }
    return ok;
}

}
