#include "health_checker.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

namespace aegis::collector {

using json = nlohmann::json;

HealthChecker::HealthChecker(const CollectorConfig& cfg)
    : cfg_(cfg),
      start_time_(std::chrono::steady_clock::now()),
      last_health_publish_(std::chrono::steady_clock::now()) {}

void HealthChecker::update_metrics(int processed, int published, int failed) {
  total_processed_ += processed;
  total_published_ += published;
  total_failed_ += failed;
}

void HealthChecker::set_source_status(const std::string& status) {
  source_status_ = status;
  spdlog::debug("Health: source_status={}", status);
}

void HealthChecker::set_kafka_status(const std::string& status, int buffer_size) {
  kafka_status_ = status;
  kafka_buffer_size_ = buffer_size;
  spdlog::debug("Health: kafka_status={} buffer_size={}", status, buffer_size);
}

void HealthChecker::set_last_error(const std::string& error) {
  last_error_ = error;
  spdlog::warn("Health: error={}", error);
}

bool HealthChecker::should_publish_health() {
  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      now - last_health_publish_).count();
  
  // Default: publish health every 60 seconds
  int health_interval_sec = 60;
  
  if (elapsed >= health_interval_sec) {
    last_health_publish_ = now;
    return true;
  }
  return false;
}

int HealthChecker::get_uptime_seconds() const {
  auto now = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::seconds>(
      now - start_time_).count();
}

std::string HealthChecker::get_current_timestamp() {
  auto now = std::time(nullptr);
  struct tm tm_buf;
#ifdef _WIN32
  localtime_s(&tm_buf, &now);
#else
  localtime_r(&now, &tm_buf);
#endif
  
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
  return oss.str();
}

std::string HealthChecker::determine_overall_health() {
  if (kafka_status_ == "error" || source_status_ == "error") {
    return "unhealthy";
  }
  
  if (kafka_status_ == "retrying" || source_status_ == "degraded") {
    return "degraded";
  }
  
  // Calculate error rate
  if (total_processed_ > 0) {
    float error_rate = static_cast<float>(total_failed_) / total_processed_;
    if (error_rate > 0.1) {  // >10% errors
      return "degraded";
    }
  }
  
  return "healthy";
}

HealthStatus HealthChecker::get_status() {
  HealthStatus status;
  status.status = determine_overall_health();
  status.events_processed = total_processed_;
  status.events_published = total_published_;
  status.events_failed = total_failed_;
  status.uptime_seconds = get_uptime_seconds();
  status.source_status = source_status_;
  status.kafka_status = kafka_status_;
  status.kafka_buffer_size = kafka_buffer_size_;
  status.last_error = last_error_;
  status.timestamp = get_current_timestamp();
  
  return status;
}

}
