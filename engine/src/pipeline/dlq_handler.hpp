#pragma once
// Publishes unprocessable messages to the dead-letter topic (siem.events.dlq) with structured error metadata appended as a JSON envelope.

#include <memory>
#include <vector>

#include "config.hpp"
#include "pipeline/kafka_producer.hpp"
#include "types.hpp"

namespace aegis::pipeline {

class DlqHandler {
public:
    explicit DlqHandler(const Config& cfg, std::shared_ptr<KafkaProducer> producer);

    // Publish a single DlqEntry to the dead-letter topic
    bool publish(const DlqEntry& entry);

    // Publish a batch of DlqEntries
    bool publish_batch(const std::vector<DlqEntry>& entries);

private:
    Config                            cfg_;
    std::shared_ptr<KafkaProducer>    producer_;
};

}
