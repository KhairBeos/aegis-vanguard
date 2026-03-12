#include "pipeline/kafka_consumer.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <stdexcept>

namespace aegis::pipeline {

KafkaConsumer::KafkaConsumer(const Config& cfg) : cfg_(cfg) {
    std::string err;
    conf_.reset(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));

    auto set = [&](const char* key, const std::string& val) {
        if (conf_->set(key, val, err) != RdKafka::Conf::CONF_OK) {
            throw std::runtime_error(
                std::string("KafkaConsumer config [") + key + "]: " + err);
        }
    };

    set("bootstrap.servers",          cfg_.kafka_brokers);
    set("group.id",                    cfg_.kafka_group_id);
    set("auto.offset.reset",           "earliest");
    set("enable.auto.commit",          "false");
    set("enable.partition.eof",        "false");
    set("session.timeout.ms",          "30000");
    set("max.poll.interval.ms",        "300000");
    set("fetch.max.bytes",             "10485760");
    set("queued.max.messages.kbytes",  "102400");

    consumer_.reset(RdKafka::KafkaConsumer::create(conf_.get(), err));
    if (!consumer_) {
        throw std::runtime_error("Failed to create Kafka consumer: " + err);
    }
}

KafkaConsumer::~KafkaConsumer() {
    if (consumer_) {
        consumer_->close();
        RdKafka::wait_destroyed(2000);
    }
}

void KafkaConsumer::start() {
    RdKafka::ErrorCode rc = consumer_->subscribe({cfg_.kafka_topic_events});
    if (rc != RdKafka::ERR_NO_ERROR) {
        throw std::runtime_error( "KafkaConsumer: subscribe to " + cfg_.kafka_topic_events + " failed: " + RdKafka::err2str(rc));
    }
    running_.store(true);
    spdlog::info("KafkaConsumer: subscribed to topic={} group={} brokers={}", cfg_.kafka_topic_events, cfg_.kafka_group_id, cfg_.kafka_brokers);
}

void KafkaConsumer::stop() {
    running_.store(false);
    spdlog::info("KafkaConsumer: shutdown requested");
}

std::vector<KafkaMessage> KafkaConsumer::poll_batch() {
    std::vector<KafkaMessage> batch;
    if (!running_.load()) return batch;

    batch.reserve(cfg_.engine_batch_size);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(cfg_.engine_batch_timeout_ms);

    while (running_.load() && static_cast<int>(batch.size()) < cfg_.engine_batch_size) {
        int remaining_ms = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>( deadline - std::chrono::steady_clock::now()).count());
        if (remaining_ms <= 0) break;

        int poll_ms = std::min(remaining_ms, cfg_.kafka_poll_timeout_ms);
        std::unique_ptr<RdKafka::Message> msg(consumer_->consume(poll_ms));

        switch (msg->err()) {
            case RdKafka::ERR_NO_ERROR: {
                const char* ptr = static_cast<const char*>(msg->payload());
                batch.push_back({
                    std::string(ptr, msg->len()),
                    msg->topic_name(),
                    msg->partition(),
                    msg->offset()});
                break;
            }
            case RdKafka::ERR__TIMED_OUT:
                // No messages available in this poll window — break to flush batch
                goto done;
            case RdKafka::ERR__PARTITION_EOF:
                spdlog::debug("KafkaConsumer: partition {} EOF", msg->partition());
                goto done;
            default:
                spdlog::error("KafkaConsumer: consume error: {}", msg->errstr());
                break;
        }
    }
done:
    return batch;
}

void KafkaConsumer::commit() {
    if (!consumer_) return;
    RdKafka::ErrorCode rc = consumer_->commitSync();
    if (rc != RdKafka::ERR_NO_ERROR) {
        spdlog::warn("KafkaConsumer: commitSync failed: {}", RdKafka::err2str(rc));
    }
}

}
