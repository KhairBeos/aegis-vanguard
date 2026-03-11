// engine/src/engine_main.cpp
// Aegis-Vanguard SIEM Engine — main entry point.
//
// Pipeline loop:
//   Kafka (siem.events)
//     → EventValidator   → [valid] → RuleEngine → AlertPublisher → Kafka/ClickHouse
//                        → [invalid] → DlqHandler → Kafka (siem.events.dlq)
//     → ClickHouseWriter (raw events)
//
// Graceful shutdown: SIGINT / SIGTERM sets the running flag to false;
// the consumer poll returns, the batch is processed, and all components flush.

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <memory>
#include <vector>

#include <spdlog/spdlog.h>

#include "config.hpp"
#include "logger.hpp"
#include "types.hpp"

#include "detection/alert_publisher.hpp"
#include "detection/rule_engine.hpp"
#include "pipeline/clickhouse_writer.hpp"
#include "pipeline/dlq_handler.hpp"
#include "pipeline/event_validator.hpp"
#include "pipeline/kafka_consumer.hpp"
#include "pipeline/kafka_producer.hpp"

// ---------------------------------------------------------------------------
// Signal handling — atomic flag checked in the poll loop
// ---------------------------------------------------------------------------

namespace {

std::atomic<bool> g_shutdown{false};
aegis::pipeline::KafkaConsumer* g_consumer_ptr{nullptr};

std::string now_utc_iso8601() {
  using clock = std::chrono::system_clock;
  const auto now = clock::now();
  const std::time_t tt = clock::to_time_t(now);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &tt);
#else
  gmtime_r(&tt, &tm);
#endif
  char buffer[21]{};
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buffer);
}

void signal_handler(int signum) {
  spdlog::warn("Received signal {} - initiating graceful shutdown", signum);
  g_shutdown.store(true);
  if (g_consumer_ptr) g_consumer_ptr->stop();
}

struct EngineMetrics {
  uint64_t validation_failures{0};
  uint64_t raw_write_failures{0};
  uint64_t alert_publish_failures{0};
  uint64_t dlq_publish_failures{0};
};

}  // anonymous namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
  // 1. Load configuration
  aegis::Config cfg;
  try {
    cfg = aegis::Config::from_env();
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "Configuration error: %s\n", ex.what());
    return EXIT_FAILURE;
  }

  // 2. Initialise structured logger
  aegis::init_logger(cfg.log_level);
  spdlog::info("=== Aegis-Vanguard Engine starting ===");
    spdlog::info("brokers={} events_topic={} batch_size={} retry_attempts={} retry_base_delay_ms={} metrics_interval_sec={} external_rules_enabled={} external_rules_dir={}",
      cfg.kafka_brokers,
      cfg.kafka_topic_events,
      cfg.engine_batch_size,
      cfg.engine_retry_max_attempts,
      cfg.engine_retry_base_delay_ms,
      cfg.engine_metrics_interval_sec,
      cfg.engine_external_rules_enabled,
      cfg.engine_external_rules_dir);

  // 3. Register signal handlers
  std::signal(SIGINT,  signal_handler);
  std::signal(SIGTERM, signal_handler);

  // 4. Construct shared components
  // KafkaProducer is shared between DlqHandler and AlertPublisher.
  auto producer      = std::make_shared<aegis::pipeline::KafkaProducer>(cfg);
  auto ch_writer     = std::make_shared<aegis::pipeline::ClickHouseWriter>(cfg);

  aegis::pipeline::KafkaConsumer consumer(cfg);
  g_consumer_ptr = &consumer;

  aegis::pipeline::EventValidator  validator;
  aegis::pipeline::DlqHandler      dlq_handler(cfg, producer);
  aegis::detection::RuleEngine     rule_engine;
  aegis::detection::AlertPublisher alert_publisher(cfg, producer, ch_writer);

  if (cfg.engine_external_rules_enabled != 0) {
    const std::size_t loaded_external = rule_engine.load_external_rules_from_dir(cfg.engine_external_rules_dir);
    spdlog::info("RuleEngine: total rules after external load={}", rule_engine.rule_count());
    if (loaded_external == 0) {
      spdlog::warn("RuleEngine: no external YAML rules loaded from {}", cfg.engine_external_rules_dir);
    }
  }

  // 5. Subscribe to events topic
  try {
    consumer.start();
  } catch (const std::exception& ex) {
    spdlog::critical("Failed to start Kafka consumer: {}", ex.what());
    return EXIT_FAILURE;
  }

  spdlog::info("Engine ready — processing events (rules={})", rule_engine.rule_count());

  // 6. Main processing loop
  uint64_t total_events   = 0;
  uint64_t total_alerts   = 0;
  uint64_t total_dlq      = 0;
  uint64_t total_batches  = 0;
  EngineMetrics metrics;
  const auto metrics_started_at = std::chrono::steady_clock::now();
  auto last_metrics_emit_at = metrics_started_at;

  while (!g_shutdown.load()) {
    // Poll a batch of raw Kafka messages
    std::vector<aegis::KafkaMessage> batch = consumer.poll_batch();
    if (batch.empty()) continue;

    ++total_batches;
    std::vector<aegis::ParsedEvent>  valid_events;
    std::vector<aegis::DlqEntry>     dlq_entries;

    valid_events.reserve(batch.size());
    dlq_entries.reserve(4);  // DLQ entries are rare in steady-state

    // --- Validate & triage ---
    for (const auto& msg : batch) {
      aegis::ValidationResult result = validator.validate(msg.payload);
      if (std::holds_alternative<aegis::ParsedEvent>(result)) {
        valid_events.push_back(std::move(std::get<aegis::ParsedEvent>(result)));
      } else {
        const auto& fail = std::get<aegis::ValidationFail>(result);
        ++metrics.validation_failures;
        spdlog::warn("Validation failed partition={} offset={}: {}",
               msg.partition, msg.offset, fail.detail);
        // Build DLQ entry with current UTC timestamp (use ts from msg if parse failed)
        aegis::DlqEntry dlq;
        dlq.raw_message  = msg.payload;
        dlq.error_reason = fail.detail;
        dlq.source_topic = msg.topic;
        dlq.partition    = msg.partition;
        dlq.offset       = msg.offset;
        dlq.ts           = now_utc_iso8601();
        dlq_entries.push_back(std::move(dlq));
      }
    }

    // --- Persist raw events to ClickHouse ---
    const bool raw_write_ok = valid_events.empty() || ch_writer->write_raw_events(valid_events);
    if (!raw_write_ok) {
      ++metrics.raw_write_failures;
      spdlog::critical("Raw event write failed; stopping engine before committing offsets");
      g_shutdown.store(true);
      consumer.stop();
      continue;
    }

    // --- Evaluate detection rules ---
    std::vector<aegis::RuleMatch> matches = rule_engine.evaluate_batch(valid_events);

    // --- Publish alerts ---
    const bool alerts_ok = alert_publisher.publish_batch(matches);
    if (!alerts_ok) {
      ++metrics.alert_publish_failures;
      spdlog::critical("Alert publish/write failed; stopping engine before committing offsets");
      g_shutdown.store(true);
      consumer.stop();
      continue;
    }

    // --- Forward DLQ entries ---
    const bool dlq_ok = dlq_handler.publish_batch(dlq_entries);
    if (!dlq_ok) {
      ++metrics.dlq_publish_failures;
      spdlog::critical("DLQ publish failed; stopping engine before committing offsets");
      g_shutdown.store(true);
      consumer.stop();
      continue;
    }

    // --- Commit offsets only after all downstream writes succeed ---
    consumer.commit();

    total_events += valid_events.size();
    total_alerts += matches.size();
    total_dlq    += dlq_entries.size();

    spdlog::debug("Batch #{}: events={} alerts={} dlq={} (totals: e={} a={} d={})",
            total_batches,
            valid_events.size(), matches.size(), dlq_entries.size(),
            total_events, total_alerts, total_dlq);

    const auto now = std::chrono::steady_clock::now();
    const auto metrics_interval = std::chrono::seconds(std::max(1, cfg.engine_metrics_interval_sec));
    if ((now - last_metrics_emit_at) >= metrics_interval) {
      const double uptime_sec = std::max(1.0,
        std::chrono::duration_cast<std::chrono::duration<double>>(now - metrics_started_at).count());
      spdlog::info(
        "Engine metrics: uptime_sec={:.1f} batches={} events={} alerts={} dlq={} eps={:.2f} aps={:.2f} validation_failures={} raw_write_failures={} alert_publish_failures={} dlq_publish_failures={}",
        uptime_sec,
        total_batches,
        total_events,
        total_alerts,
        total_dlq,
        static_cast<double>(total_events) / uptime_sec,
        static_cast<double>(total_alerts) / uptime_sec,
        metrics.validation_failures,
        metrics.raw_write_failures,
        metrics.alert_publish_failures,
        metrics.dlq_publish_failures);
      last_metrics_emit_at = now;
    }
  }

  // 7. Graceful shutdown
    spdlog::info("=== Engine shutdown: total_events={} total_alerts={} total_dlq={} batches={} validation_failures={} raw_write_failures={} alert_publish_failures={} dlq_publish_failures={} ===",
      total_events,
      total_alerts,
      total_dlq,
      total_batches,
      metrics.validation_failures,
      metrics.raw_write_failures,
      metrics.alert_publish_failures,
      metrics.dlq_publish_failures);
  producer->flush(5000);
  return EXIT_SUCCESS;
}
