#pragma once
// Thin RAII wrapper around librdkafka RdKafka::Producer
// Used by DlqHandler and AlertPublisher to publish outbound messages

#include <rdkafkacpp.h>

#include <cstdint>
#include <memory>
#include <string>

#include "config.hpp"

namespace aegis::pipeline {

class KafkaProducer {
public:
    explicit KafkaProducer(const Config& cfg);
    ~KafkaProducer();

    // Publish a message
    // Returns false on immediate produce failure
    bool produce(const std::string& topic,
                 const std::string& key,
                 const std::string& value);

    // Flush all in-flight messages with a timeout (default 5s)
    void flush(int timeout_ms = 5000);

private:
    Config                               cfg_;
    std::unique_ptr<RdKafka::Producer>   producer_;
    std::unique_ptr<RdKafka::Conf>       conf_;
    std::unique_ptr<RdKafka::Topic>      last_topic_;  // cached topic handle

    // Return or create a topic handle for the given topic name (thread-local cache)
    RdKafka::Topic* get_topic(const std::string& name);

    int retry_delay_ms(int attempt) const noexcept;

    // Delivery-report event callback implementation for logging delivery errors
    class DeliveryReporter final : public RdKafka::EventCb {
    public:
        void event_cb(RdKafka::Event& event) override;
    };

    DeliveryReporter dr_cb_;
};

}
