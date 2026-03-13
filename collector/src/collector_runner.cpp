#include "collector_runner.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <memory>
#include <thread>

#include <spdlog/spdlog.h>

#include "event_builder.hpp"
#include "kafka_event_producer.hpp"
#include "sources/event_source.hpp"
#include "sources/fixture_event_source.hpp"
#include "sources/linux_ebpf_event_source.hpp"
#include "sources/synthetic_event_source.hpp"

namespace aegis::collector {
namespace {

std::atomic<bool> g_shutdown{false};

void signal_handler(int signum) {
  spdlog::warn("Collector received signal {} - shutting down", signum);
  g_shutdown.store(true);
}

std::unique_ptr<IEventSource> make_source(const CollectorConfig& cfg) {
  if (cfg.runtime.source_kind == "fixture") {
    if (cfg.runtime.fixture_path.empty()) {
      throw std::runtime_error("runtime.fixture_path is required when source=fixture");
    }
    return std::make_unique<FixtureEventSource>(cfg.runtime.fixture_path);
  }
  if (cfg.runtime.source_kind == "ebpf") {
    return std::make_unique<LinuxEbpfEventSource>(cfg);
  }
  return std::make_unique<SyntheticEventSource>(cfg);
}

}  // namespace

CollectorRunner::CollectorRunner(CollectorConfig cfg, std::string config_path)
    : cfg_(std::move(cfg)),
      config_path_(std::move(config_path)),
      config_reloader_(std::make_unique<ConfigReloader>(config_path_)),
      health_checker_(std::make_unique<HealthChecker>(cfg_)) {
  // Register config reloader for SIGHUP signals
  ConfigReloader::register_global_handler(config_reloader_.get());
}

int CollectorRunner::run() {
  std::signal(SIGINT, signal_handler);
  std::signal(SIGTERM, signal_handler);

  CanonicalEventBuilder builder(cfg_);
  std::unique_ptr<IEventSource> source = make_source(cfg_);
  std::unique_ptr<KafkaEventProducer> producer;
  if (!cfg_.runtime.dry_run) {
    producer = std::make_unique<KafkaEventProducer>(cfg_);
  }

  spdlog::info("Collector starting source={} host={} agent_id={} max_events={}",
               source->name(),
               cfg_.hostname,
               cfg_.agent_id,
               cfg_.runtime.max_events);

  int published = 0;
  int skipped = 0;
  int health_publish_count = 0;
  auto last_retry_check = std::chrono::steady_clock::now();

  while (!g_shutdown.load()) {
    // Check for config hot-reload (SIGHUP)
    if (config_reloader_->check_reload_signal()) {
      try {
        cfg_ = config_reloader_->reload_config();
        builder = CanonicalEventBuilder(cfg_);
        spdlog::info("Config reloaded: reload_count={}", config_reloader_->get_reload_count());
      } catch (const std::exception& ex) {
        spdlog::error("Failed to reload config: {}", ex.what());
      }
    }

    // Try to read event from source
    std::optional<SourceRecord> record = source->next_event();
    if (!record.has_value()) {
      // Check if source is exhausted
      if (source->is_exhausted()) {
        spdlog::info("Source exhausted, exiting");
        health_checker_->set_source_status("exhausted");
        break;
      }

      // Source dry (temporarily), process retries and health checks
      if (producer) {
        // Process retry queue (exponential backoff)
        auto now = std::chrono::steady_clock::now();
        auto since_last_retry = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - last_retry_check).count();

        if (since_last_retry >= cfg_.runtime.poll_interval_ms) {
          producer->process_retries();
          last_retry_check = now;

          // Check backpressure
          if (producer->is_backpressured()) {
            health_checker_->set_kafka_status("backpressured", producer->get_buffer_size());
            spdlog::warn("Kafka backpressure detected: buffer_size={}", producer->get_buffer_size());
          } else {
            health_checker_->set_kafka_status("connected", producer->get_buffer_size());
          }
        }

        // Publish health check periodically
        if (health_checker_->should_publish_health()) {
          const auto health_status = health_checker_->get_status();
          const std::string health_json = builder.build_health_event(health_status);
          if (producer->publish(cfg_.agent_id, health_json)) {
            ++health_publish_count;
            spdlog::debug("Health check published (#{}, status={})",
                          health_publish_count, health_status.status);
          }
        }
      }

      std::this_thread::sleep_for(
          std::chrono::milliseconds(std::max(1, cfg_.runtime.poll_interval_ms)));
      continue;
    }

    // Got an event, process it
    if (!is_collection_enabled(cfg_, *record)) {
      ++skipped;
      health_checker_->update_metrics(1, 0, 0);
      continue;
    }

    const std::string event_json = builder.build(*record);

    if (cfg_.runtime.dry_run) {
      spdlog::info("Collector dry-run event={}", event_json);
      ++published;
      health_checker_->update_metrics(1, 1, 0);
    } else if (!producer) {
      spdlog::error("No producer available (dry_run=false but producer not initialized)");
      health_checker_->update_metrics(1, 0, 1);
      health_checker_->set_kafka_status("error");
      return 1;
    } else {
      // Publish with backpressure handling
      if (producer->publish(cfg_.hostname, event_json)) {
        ++published;
        health_checker_->update_metrics(1, 1, 0);
        spdlog::info("Collector published event #{} type={}", published, event_type_of(*record));
      } else {
        // Still queued for retry (backpressure)
        spdlog::debug("Event queued for retry");
        health_checker_->update_metrics(1, 0, 0);
      }
    }

    if (cfg_.runtime.max_events > 0 && published >= cfg_.runtime.max_events) {
      spdlog::info("Reached max_events limit: {}", cfg_.runtime.max_events);
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(std::max(1, cfg_.runtime.poll_interval_ms)));
  }

  // Graceful shutdown
  spdlog::info("Collector shutting down...");

  health_checker_->set_source_status("stopped");
  
  if (producer) {
    spdlog::info("Flushing remaining events (buffer_size={})...", producer->get_buffer_size());
    producer->flush();

    // Log final producer stats
    auto stats = producer->get_stats();
    spdlog::info("Kafka producer final stats: published={} retried={} failed={} buffered={}",
                 stats.published, stats.retried, stats.failed, stats.buffered);
  }

  // Final health report
  auto final_status = health_checker_->get_status();
  spdlog::info("Collector shutdown: status={} published={} failed={} uptime={}s",
               final_status.status,
               final_status.events_published,
               final_status.events_failed,
               final_status.uptime_seconds);

  if (producer && !cfg_.runtime.dry_run) {
    producer->publish(cfg_.agent_id, builder.build_health_event(health_checker_->get_status()));
  }

  spdlog::info("Collector exiting published={} skipped={} source={} reloads={}",
               published, skipped, source->name(), config_reloader_->get_reload_count());
  return 0;
}

}  // namespace aegis::collector