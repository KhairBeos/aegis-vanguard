#include "event_builder.hpp"

#include <chrono>
#include <ctime>
#include <random>
#include <string_view>

#include <nlohmann/json.hpp>

#include "crypto/sha256.hpp"

namespace aegis::collector {
namespace {

using json = nlohmann::json;

std::string now_utc_iso8601() {
  using clock = std::chrono::system_clock;
  const std::time_t tt = clock::to_time_t(clock::now());
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

std::string random_hex(std::size_t length) {
  thread_local std::mt19937_64 rng{
    static_cast<std::uint64_t>(
      std::chrono::steady_clock::now().time_since_epoch().count())};
  static constexpr std::string_view alphabet = "0123456789abcdef";

  std::string out;
  out.reserve(length);
  for (std::size_t i = 0; i < length; ++i) {
    out.push_back(alphabet[static_cast<std::size_t>(rng() % alphabet.size())]);
  }
  return out;
}

std::string make_process_guid(const std::string& host, std::uint32_t pid, const std::string& identity_time) {
  const std::string seed = host + "|" + std::to_string(pid) + "|" + identity_time;
  return crypto::sha256_hex(seed);
}

std::string source_label(const CollectorConfig& cfg) {
  if (cfg.runtime.source_kind == "ebpf") return "collector.ebpf";
  if (cfg.runtime.source_kind == "fixture") return "collector.fixture";
  return "collector.app";
}

std::string severity_for(const SourceRecord& record) {
  if (std::holds_alternative<AuthFailureRecord>(record)) return "medium";
  return "info";
}

std::string severity_for_health(const HealthStatus& status) {
  if (status.status == "unhealthy") return "high";
  if (status.status == "degraded") return "medium";
  return "info";
}

std::string event_timestamp_of(const SourceRecord& record) {
  return std::visit([](const auto& item) {
    return item.ts.empty() ? now_utc_iso8601() : item.ts;
  }, record);
}

}  // namespace

bool is_collection_enabled(const CollectorConfig& cfg, const SourceRecord& record) {
  if (std::holds_alternative<ProcessStartRecord>(record)) return cfg.collection.process_events;
  if (std::holds_alternative<NetworkConnectRecord>(record)) return cfg.collection.network_events;
  if (std::holds_alternative<FileOpenRecord>(record)) return cfg.collection.file_events;
  return cfg.collection.auth_events;
}

std::string CanonicalEventBuilder::build(const SourceRecord& record) const {
  json envelope;
  envelope["schema_version"] = "v1.1";
  envelope["event_id"] = random_hex(32);
  envelope["ts"] = event_timestamp_of(record);
  envelope["host"] = cfg_.hostname;
  envelope["agent_id"] = cfg_.agent_id;
  envelope["source"] = source_label(cfg_);
  envelope["event_type"] = event_type_of(record);
  envelope["severity"] = severity_for(record);
  envelope["tenant_id"] = cfg_.runtime.tenant_id;
  envelope["trace_id"] = random_hex(32);

  json payload = json::object();
  std::string process_guid;

  std::visit([&](const auto& item) {
    using T = std::decay_t<decltype(item)>;
    if constexpr (std::is_same_v<T, ProcessStartRecord>) {
      const std::string process_time = item.process_start_time.empty() ? envelope["ts"].get<std::string>() : item.process_start_time;
      process_guid = item.process_guid.empty()
        ? make_process_guid(cfg_.hostname, item.pid, process_time)
        : item.process_guid;

      payload["process"] = {
        {"pid", item.pid},
        {"ppid", item.ppid},
        {"uid", item.uid},
        {"user_name", item.user_name},
        {"name", item.name},
        {"exe", item.exe},
        {"cmdline", item.cmdline},
        {"process_start_time", process_time},
      };
    } else if constexpr (std::is_same_v<T, NetworkConnectRecord>) {
      process_guid = item.process_guid.empty()
        ? make_process_guid(cfg_.hostname, item.pid, envelope["ts"].get<std::string>())
        : item.process_guid;
      payload["network"] = {
        {"pid", item.pid},
        {"process_guid", process_guid},
        {"protocol", item.protocol},
        {"src_ip", item.src_ip},
        {"src_port", item.src_port},
        {"dst_ip", item.dst_ip},
        {"dst_port", item.dst_port},
        {"direction", item.direction},
      };
    } else if constexpr (std::is_same_v<T, FileOpenRecord>) {
      process_guid = item.process_guid.empty()
        ? make_process_guid(cfg_.hostname, item.pid, envelope["ts"].get<std::string>())
        : item.process_guid;
      payload["file"] = {
        {"pid", item.pid},
        {"process_guid", process_guid},
        {"user_name", item.user_name},
        {"path", item.path},
        {"flags", item.flags},
        {"result", item.result},
      };
    } else if constexpr (std::is_same_v<T, AuthFailureRecord>) {
      payload["auth"] = {
        {"user_name", item.user_name},
        {"method", item.method},
        {"src_ip", item.src_ip},
        {"reason", item.reason},
      };
    }
  }, record);

  if (!process_guid.empty()) {
    envelope["process_guid"] = process_guid;
  }
  envelope["event"] = payload;
  return envelope.dump();
}

std::string CanonicalEventBuilder::build_health_event(const HealthStatus& status) const {
  json envelope;
  envelope["schema_version"] = "v1.1";
  envelope["event_id"] = random_hex(32);
  envelope["ts"] = status.timestamp.empty() ? now_utc_iso8601() : status.timestamp;
  envelope["host"] = cfg_.hostname;
  envelope["agent_id"] = cfg_.agent_id;
  envelope["source"] = "collector.health";
  envelope["event_type"] = "health_check";
  envelope["severity"] = severity_for_health(status);
  envelope["tenant_id"] = cfg_.runtime.tenant_id;
  envelope["trace_id"] = random_hex(32);
  envelope["event"] = {
    {"health", {
      {"status", status.status},
      {"metrics", {
        {"events_processed", status.events_processed},
        {"events_published", status.events_published},
        {"events_failed", status.events_failed},
        {"uptime_seconds", status.uptime_seconds},
      }},
      {"components", {
        {"source", status.source_status},
        {"kafka", status.kafka_status},
        {"kafka_buffer_size", status.kafka_buffer_size},
      }},
    }}
  };

  if (!status.last_error.empty()) {
    envelope["event"]["health"]["last_error"] = status.last_error;
  }

  return envelope.dump();
}

}  // namespace aegis::collector
