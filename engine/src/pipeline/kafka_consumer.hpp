#pragma once
// Batch-polling Kafka consumer. The main engine loop calls poll_batch() to receive up to engine_batch_size messages, then processes and commits them.

#include <rdkafkacpp.h>

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "config.hpp"
#include "types.hpp"

namespace aegis::pipeline {

class KafkaConsumer {
public:
    explicit KafkaConsumer(const Config& cfg);
    ~KafkaConsumer();

    void start();

    void stop();

    // Poll Kafka and return a batch of up to cfg.engine_batch_size messages
    // Blocks for at most cfg.engine_batch_timeout_ms total
    // Returns an empty vector when stopped
    std::vector<KafkaMessage> poll_batch();

    // Synchronously commit offsets for the last returned batch
    void commit();

    bool is_running() const noexcept { return running_.load(); }

private:
    const Config&                            cfg_;
    std::atomic<bool>                        running_{false};
    std::unique_ptr<RdKafka::KafkaConsumer>  consumer_;
    std::unique_ptr<RdKafka::Conf>           conf_;
};

}
