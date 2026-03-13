#include "kafka_event_producer.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <thread>

#include <spdlog/spdlog.h>

namespace aegis::collector {

void KafkaEventProducer::EventLogger::event_cb(RdKafka::Event& event) {
  if (event.type() == RdKafka::Event::EVENT_ERROR) {
    spdlog::error("Collector Kafka producer error: {} ({})", event.str(), RdKafka::err2str(event.err()));
  }
}

KafkaEventProducer::KafkaEventProducer(const CollectorConfig& cfg) : cfg_(cfg) {
  std::string error;
  conf_.reset(RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL));
  if (!conf_) {
    throw std::runtime_error("Failed to allocate Kafka producer config");
  }

  const std::string brokers = [&]() {
    std::string out;
    for (std::size_t index = 0; index < cfg_.kafka.brokers.size(); ++index) {
      if (index > 0) out += ",";
      out += cfg_.kafka.brokers[index];
    }
    return out;
  }();

  auto set = [&](const char* key, const std::string& value) {
    if (conf_->set(key, value, error) != RdKafka::Conf::CONF_OK) {
      throw std::runtime_error(std::string("Collector Kafka config [") + key + "]: " + error);
    }
  };

  set("bootstrap.servers", brokers);
  set("queue.buffering.max.ms", "50");
  set("message.send.max.retries", std::to_string(std::max(1, cfg_.kafka.retry_max_attempts)));
  set("retry.backoff.ms", std::to_string(std::max(1, cfg_.kafka.retry_base_delay_ms)));

  // Enable compression for batched events (lz4 is always bundled in librdkafka)
  set("compression.type", "lz4");
  
  // Increase batch size for throughput
  set("linger.ms", "10");
  set("batch.size", "16384");

  if (conf_->set("event_cb", &event_logger_, error) != RdKafka::Conf::CONF_OK) {
    throw std::runtime_error("Collector Kafka config [event_cb]: " + error);
  }

  producer_.reset(RdKafka::Producer::create(conf_.get(), error));
  if (!producer_) {
    throw std::runtime_error("Failed to create collector Kafka producer: " + error);
  }

  spdlog::info("Kafka producer initialized: brokers={}, topic={}, max_buffer={}, max_retries={}",
               brokers, cfg_.kafka.topic, max_buffer_size_, max_retries_);
}

KafkaEventProducer::~KafkaEventProducer() {
  flush();
}

RdKafka::Topic* KafkaEventProducer::get_topic(const std::string& name) {
  const auto it = topic_cache_.find(name);
  if (it != topic_cache_.end()) {
    return it->second.get();
  }

  std::string error;
  std::unique_ptr<RdKafka::Conf> topic_conf(RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC));
  std::unique_ptr<RdKafka::Topic> topic(RdKafka::Topic::create(producer_.get(), name, topic_conf.get(), error));
  if (!topic) {
    throw std::runtime_error("Failed to create topic handle for " + name + ": " + error);
  }

  auto [inserted_it, _] = topic_cache_.emplace(name, std::move(topic));
  return inserted_it->second.get();
}

int KafkaEventProducer::calculate_backoff_delay(int retry_count) const noexcept {
  // Exponential backoff: initial * (multiplier ^ retry_count)
  float delay = initial_retry_delay_ms_ *
                std::pow(backoff_multiplier_, std::min(retry_count, 5));
  return std::min(static_cast<int>(delay), max_retry_delay_ms_);
}

bool KafkaEventProducer::try_publish_single(const std::string& key, const std::string& value) {
  // Non-blocking publish attempt
  RdKafka::Topic* topic = get_topic(cfg_.kafka.topic);
  producer_->poll(0);
  
  const RdKafka::ErrorCode rc = producer_->produce(
    topic,
    RdKafka::Topic::PARTITION_UA,
    RdKafka::Producer::RK_MSG_COPY,
    const_cast<char*>(value.data()),
    value.size(),
    key.empty() ? nullptr : reinterpret_cast<const void*>(key.data()),
    key.size(),
    nullptr);

  if (rc == RdKafka::ERR_NO_ERROR) {
    ++total_published_;
    return true;
  }

  if (rc == RdKafka::ERR__QUEUE_FULL) {
    spdlog::debug("Kafka queue full, buffering event (buffer_size={})", queue_.size());
  } else {
    spdlog::warn("Kafka produce error: {}", RdKafka::err2str(rc));
  }

  return false;
}

bool KafkaEventProducer::publish(const std::string& key, const std::string& value) {
  // Try direct publish first
  if (try_publish_single(key, value)) {
    return true;
  }

  // If backpressure or error, queue for retry
  if (is_backpressured()) {
    spdlog::warn("Kafka backpressure: buffer full (size={}), dropping event", queue_.size());
    ++total_failed_;
    return false;
  }

  queue_.push_back(PublishEvent{key, value, 0, std::chrono::steady_clock::now()});
  spdlog::debug("Event queued for retry (queue_size={})", queue_.size());
  return true;  // Queued for retry
}

bool KafkaEventProducer::publish_batch(const std::vector<std::pair<std::string, std::string>>& events) {
  spdlog::info("Publishing batch of {} events", events.size());
  
  int published = 0;
  for (const auto& [key, value] : events) {
    if (try_publish_single(key, value)) {
      ++published;
    } else {
      // Queue failed event for retry
      if (!is_backpressured()) {
        queue_.push_back(PublishEvent{key, value, 0, std::chrono::steady_clock::now()});
      } else {
        ++total_failed_;
      }
    }
  }

  spdlog::info("Batch publish: {}/{} successful, {} queued", published, events.size(), queue_.size());
  return published == static_cast<int>(events.size());
}

bool KafkaEventProducer::is_ready_for_retry(const PublishEvent& event) const {
  int delay_ms = calculate_backoff_delay(event.retry_count);
  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - event.last_attempt).count();
  return elapsed >= delay_ms;
}

void KafkaEventProducer::process_retries() {
  if (queue_.empty()) {
    return;
  }

  auto now = std::chrono::steady_clock::now();
  std::deque<PublishEvent> retry_queue;

  while (!queue_.empty()) {
    PublishEvent event = std::move(queue_.front());
    queue_.pop_front();

    if (is_ready_for_retry(event)) {
      // Try to publish
      if (try_publish_single(event.key, event.value)) {
        ++total_retried_;
        spdlog::debug("Retry {} succeeded (attempt_#{})", event.key, event.retry_count + 1);
        continue;
      }

      // Still failing, check if should keep retrying
      event.retry_count++;
      event.last_attempt = now;

      if (event.retry_count >= max_retries_) {
        ++total_failed_;
        spdlog::error("Event exhausted retries (attempts={})", event.retry_count);
        continue;
      }

      // Re-queue for next retry
      retry_queue.push_back(std::move(event));
    } else {
      // Not ready yet, re-queue
      retry_queue.push_back(std::move(event));
    }

    // Stop processing if queue would exceed backpressure
    if (retry_queue.size() + queue_.size() >= static_cast<size_t>(max_buffer_size_)) {
      spdlog::warn("Retry queue approaching backpressure: size={}", retry_queue.size());
      break;
    }
  }

  // Restore queue with unprocessed events
  queue_ = std::move(retry_queue);

  if (!queue_.empty()) {
    spdlog::debug("Retry queue size: {}", queue_.size());
  }
}

void KafkaEventProducer::flush() {
  if (!producer_) return;

  // First, process any pending retries
  process_retries();

  // Try to publish remaining queued events
  if (!queue_.empty()) {
    spdlog::warn("Flushing with {} events still in queue", queue_.size());
  }

  const RdKafka::ErrorCode rc = producer_->flush(cfg_.kafka.flush_timeout_ms);
  if (rc != RdKafka::ERR_NO_ERROR) {
    spdlog::warn("Collector flush incomplete: {}", RdKafka::err2str(rc));
  }

  if (!queue_.empty()) {
    spdlog::error("Flush complete but {} events remain in queue", queue_.size());
  }
}

KafkaEventProducer::Stats KafkaEventProducer::get_stats() const {
  return {
    total_published_,
    total_retried_,
    total_failed_,
    static_cast<int>(queue_.size())
  };
}


}  // namespace aegis::collector