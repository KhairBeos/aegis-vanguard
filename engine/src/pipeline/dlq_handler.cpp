// engine/src/pipeline/dlq_handler.cpp
#include "pipeline/dlq_handler.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace aegis::pipeline {

using json = nlohmann::json;

DlqHandler::DlqHandler(const Config& cfg, std::shared_ptr<KafkaProducer> producer)
    : cfg_(cfg), producer_(std::move(producer)) {}

bool DlqHandler::publish(const DlqEntry& entry) {
    // Wrap original payload and error metadata in a structured envelope.
    // Consumers of the DLQ topic can use this to replay or investigate.
    json envelope;
    envelope["ts"]             = entry.ts;
    envelope["error_reason"]   = entry.error_reason;
    envelope["source_topic"]   = entry.source_topic;
    envelope["partition"]      = entry.partition;
    envelope["offset"]         = entry.offset;
    // Store original payload as-is (may be malformed JSON — store as string).
    envelope["original"]       = entry.raw_message;

    try {
        if (!producer_->produce(cfg_.kafka_topic_dlq, /*key=*/"", envelope.dump())) {
            return false;
        }
        spdlog::warn("DlqHandler: published DLQ entry reason=\"{}\" offset={}",
                     entry.error_reason, entry.offset);
    } catch (const std::exception& ex) {
        spdlog::error("DlqHandler: failed to publish DLQ entry: {}", ex.what());
        return false;
    }
    return true;
}

bool DlqHandler::publish_batch(const std::vector<DlqEntry>& entries) {
    bool ok = true;
    for (const auto& e : entries) {
        ok = publish(e) && ok;
    }
    return ok;
}

}  // namespace aegis::pipeline
