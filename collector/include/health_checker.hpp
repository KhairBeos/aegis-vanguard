#pragma once

#include <chrono>
#include <string>
#include <memory>

#include "config.hpp"

namespace aegis::collector {

/// Health check status and metrics
struct HealthStatus {
  std::string status;  // "healthy", "degraded", "unhealthy"
  int events_processed{0};
  int events_published{0};
  int events_failed{0};
  int uptime_seconds{0};
  float cpu_percent{0.0f};
  float memory_mb{0.0f};
  std::string source_status;  // "running", "exhausted", "error"
  std::string kafka_status;   // "connected", "retrying", "error"
  int kafka_buffer_size{0};
  std::string last_error;
  std::string timestamp;
};

/// Produces periodic health check events to Kafka
class HealthChecker {
public:
  explicit HealthChecker(const CollectorConfig& cfg);
  
  /// Update current metrics
  void update_metrics(int processed, int published, int failed);
  
  /// Update source status
  void set_source_status(const std::string& status);
  
  /// Update Kafka status
  void set_kafka_status(const std::string& status, int buffer_size = 0);
  
  /// Record last error
  void set_last_error(const std::string& error);
  
  /// Check if should publish health event (time-based)
  bool should_publish_health();
  
  /// Get current health status
  HealthStatus get_status();
  

private:
  CollectorConfig cfg_;
  std::chrono::steady_clock::time_point start_time_;
  std::chrono::steady_clock::time_point last_health_publish_;
  
  int total_processed_{0};
  int total_published_{0};
  int total_failed_{0};
  std::string source_status_{"running"};
  std::string kafka_status_{"connected"};
  int kafka_buffer_size_{0};
  std::string last_error_;
  
  int get_uptime_seconds() const;
  std::string determine_overall_health();
  std::string get_current_timestamp();
};

}  // namespace aegis::collector
