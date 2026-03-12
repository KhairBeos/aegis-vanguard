#pragma once
// Serialises a RuleMatch into the api_spec v1.1 alert JSON, publishes it to the siem.alerts Kafka topic, and persists it to the ClickHouse aegis.alerts table.

#include <memory>
#include <vector>

#include "config.hpp"
#include "detection/rule.hpp"
#include "pipeline/clickhouse_writer.hpp"
#include "pipeline/kafka_producer.hpp"
#include "types.hpp"

namespace aegis::detection {

class AlertPublisher {
public:
    AlertPublisher(const Config& cfg, std::shared_ptr<pipeline::KafkaProducer>  producer, std::shared_ptr<pipeline::ClickHouseWriter> ch_writer);

    // Publish a single alert
    bool publish(const RuleMatch& match);

    // Publish a batch of alerts
    bool publish_batch(const std::vector<RuleMatch>& matches);

private:
    Config cfg_;
    std::shared_ptr<pipeline::KafkaProducer>   producer_;
    std::shared_ptr<pipeline::ClickHouseWriter> ch_writer_;

    // Build the api_spec v1.1 alert JSON string for a RuleMatch
    static std::string build_alert_json(const RuleMatch& match);

    // Generate a time-based unique alert ID (compact UUID4 hex)
    static std::string generate_alert_id();
};

}
