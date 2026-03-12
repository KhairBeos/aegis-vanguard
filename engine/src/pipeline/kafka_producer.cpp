#include "pipeline/kafka_producer.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <unordered_map>

namespace aegis::pipeline {

// DeliveryReporter
void KafkaProducer::DeliveryReporter::event_cb(RdKafka::Event& event) {
    switch (event.type()) {
        case RdKafka::Event::EVENT_ERROR:
            spdlog::error("KafkaProducer: error: {} ({})",
                          event.str(), RdKafka::err2str(event.err()));
            break;
        case RdKafka::Event::EVENT_LOG:
            spdlog::debug("KafkaProducer: rdkafka log [{}]: {}", event.fac(), event.str());
            break;
        default:
            break;
    }
}

// KafkaProducer
KafkaProducer::KafkaProducer(const Config& cfg) : cfg_(cfg) {
    std::string err;
    conf_.reset(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

    auto set = [&](const char* key, const std::string& val) {
        if (conf_->set(key, val, err) != RdKafka::Conf::CONF_OK) {
            throw std::runtime_error(
                std::string("KafkaProducer config [") + key + "]: " + err);
        }
    };

    set("bootstrap.servers",    cfg.kafka_brokers);
    set("queue.buffering.max.ms", "50"); // low latency for alerts/dlq
    set("message.send.max.retries", "3");
    set("retry.backoff.ms", "500");

    if (conf_->set("event_cb", &dr_cb_, err) != RdKafka::Conf::CONF_OK) {
        throw std::runtime_error("KafkaProducer: set event_cb: " + err);
    }

    producer_.reset(RdKafka::Producer::create(conf_.get(), err));
    if (!producer_) {
        throw std::runtime_error("Failed to create Kafka producer: " + err);
    }
    spdlog::info("KafkaProducer: connected to brokers={}", cfg.kafka_brokers);
}

KafkaProducer::~KafkaProducer() {
    if (producer_) {
        flush(5000);
    }
}

RdKafka::Topic* KafkaProducer::get_topic(const std::string& name) {
    // Use a static per-instance map to cache topic handles
    static thread_local std::unordered_map<std::string, std::unique_ptr<RdKafka::Topic>> cache;
    auto it = cache.find(name);
    if (it != cache.end()) return it->second.get();

    std::string err;
    std::unique_ptr<RdKafka::Conf> tconf(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC));
    auto* topic = RdKafka::Topic::create(producer_.get(), name, tconf.get(), err);
    if (!topic) {
        throw std::runtime_error("KafkaProducer: create topic [" + name + "]: " + err);
    }
    cache[name].reset(topic);
    return cache[name].get();
}

bool KafkaProducer::produce(const std::string& topic_name,
                            const std::string& key,
                            const std::string& value) {
    auto* topic = get_topic(topic_name);

    for (int attempt = 1; attempt <= std::max(1, cfg_.engine_retry_max_attempts); ++attempt) {
        producer_->poll(0);

        // Copy value into payload — rdkafka takes ownership when RK_MSG_COPY is set
        RdKafka::ErrorCode rc = producer_->produce(
            topic,
            RdKafka::Topic::PARTITION_UA,
            RdKafka::Producer::RK_MSG_COPY,
            const_cast<char*>(value.data()),
            value.size(),
            key.empty() ? nullptr : reinterpret_cast<const void*>(key.data()),
            key.size(),
            nullptr);

        if (rc == RdKafka::ERR_NO_ERROR) {
            return true;
        }

        const int delay_ms = retry_delay_ms(attempt);
        spdlog::warn("KafkaProducer: produce to {} failed attempt {}/{}: {}",
                     topic_name,
                     attempt,
                     std::max(1, cfg_.engine_retry_max_attempts),
                     RdKafka::err2str(rc));

        if (attempt < std::max(1, cfg_.engine_retry_max_attempts)) {
            producer_->poll(delay_ms);
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
    }

    spdlog::error("KafkaProducer: exhausted retries for topic={}", topic_name);
    return false;
}

void KafkaProducer::flush(int timeout_ms) {
    if (!producer_) return;
    RdKafka::ErrorCode rc = producer_->flush(timeout_ms);
    if (rc != RdKafka::ERR_NO_ERROR) {
        spdlog::warn("KafkaProducer: flush incomplete ({}): {}",
                     timeout_ms, RdKafka::err2str(rc));
    }
}

int KafkaProducer::retry_delay_ms(int attempt) const noexcept {
    const int bounded_attempt = std::max(0, attempt - 1);
    const int base_delay = std::max(1, cfg_.engine_retry_base_delay_ms);
    const int multiplier = 1 << std::min(bounded_attempt, 4);
    return std::min(base_delay * multiplier, 5000);
}

}
