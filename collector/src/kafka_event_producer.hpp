#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <rdkafkacpp.h>

#include "config.hpp"

namespace aegis::collector {

// Publish event with retry metadata
struct PublishEvent {
  std::string key;
  std::string value;
  int retry_count{0};
  std::chrono::steady_clock::time_point last_attempt;
};

/// Produces events to Kafka with advanced features:
/// - Retry logic with exponential backoff
/// - Batch publishing for throughput
/// - Backpressure buffer queue
/// - Delivery callbacks and error handling
class KafkaEventProducer {
public:
  explicit KafkaEventProducer(const CollectorConfig& cfg);
  ~KafkaEventProducer();

  /// Publish single event (queued if backpressure)
  bool publish(const std::string& key, const std::string& value);

  /// Publish batch of events atomically
  bool publish_batch(const std::vector<std::pair<std::string, std::string>>& events);

  /// Process retry queue and handle backpressure
  void process_retries();

  /// Get current buffer size (backpressure indicator)
  int get_buffer_size() const { return queue_.size(); }

  /// Check if buffer is at backpressure threshold
  bool is_backpressured() const { return get_buffer_size() >= max_buffer_size_; }

  /// Flush all pending events with timeout
  void flush();

  /// Get producer statistics
  struct Stats {
    int published{0};
    int retried{0};
    int failed{0};
    int buffered{0};
  };
  Stats get_stats() const;

private:
  CollectorConfig cfg_;
  std::unique_ptr<RdKafka::Producer> producer_;
  std::unique_ptr<RdKafka::Conf> conf_;
  std::unordered_map<std::string, std::unique_ptr<RdKafka::Topic>> topic_cache_;
  
  // Backpressure queue for events that fail or when buffer full
  std::deque<PublishEvent> queue_;
  int max_buffer_size_{10000};  // Max events in queue before backpressure
  
  // Retry policy
  int max_retries_{3};
  int initial_retry_delay_ms_{250};
  float backoff_multiplier_{2.0f};
  int max_retry_delay_ms_{30000};  // 30 seconds cap
  
  // Statistics
  int total_published_{0};
  int total_retried_{0};
  int total_failed_{0};

  class EventLogger final : public RdKafka::EventCb {
  public:
    void event_cb(RdKafka::Event& event) override;
  } event_logger_;

  RdKafka::Topic* get_topic(const std::string& name);
  
  /// Calculate exponential backoff delay
  int calculate_backoff_delay(int retry_count) const noexcept;
  
  /// Try to publish single event (no retry)
  bool try_publish_single(const std::string& key, const std::string& value);
  
  /// Check if event ready for retry
  bool is_ready_for_retry(const PublishEvent& event) const;
};

}