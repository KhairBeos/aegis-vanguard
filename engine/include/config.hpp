#pragma once
// engine/include/config.hpp — Runtime configuration loaded from environment variables.
// All settings have sane defaults so the engine works out-of-the-box with the
// deploy/docker-compose stack.

#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace aegis {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

inline std::string env_str(const char* var, const char* default_val) {
    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
    return v ? std::string(v) : std::string(default_val);
}

inline int env_int(const char* var, int default_val) {
    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
    if (!v) return default_val;
    try {
        return std::stoi(v);
    } catch (...) {
        return default_val;
    }
}

inline uint16_t env_uint16(const char* var, uint16_t default_val) {
    const char* v = std::getenv(var);  // NOLINT(concurrency-mt-unsafe)
    if (!v) return default_val;
    try {
        int val = std::stoi(v);
        if (val < 0 || val > 65535)
            throw std::out_of_range("port out of range");
        return static_cast<uint16_t>(val);
    } catch (...) {
        return default_val;
    }
}

// ---------------------------------------------------------------------------
// Config struct
// ---------------------------------------------------------------------------

struct Config {
    // --- Kafka ---
    std::string kafka_brokers;        // e.g. "localhost:9092"
    std::string kafka_group_id;       // consumer group
    std::string kafka_topic_events;   // inbound raw events
    std::string kafka_topic_alerts;   // outbound alert output
    std::string kafka_topic_dlq;      // dead-letter queue

    int kafka_poll_timeout_ms;        // single poll timeout
    int engine_batch_size;            // max events per processing batch
    int engine_batch_timeout_ms;      // max milliseconds to fill a batch
    int engine_retry_max_attempts;    // shared retry count for transient downstream failures
    int engine_retry_base_delay_ms;   // exponential backoff base delay
    int engine_metrics_interval_sec;  // periodic health/throughput log interval
    int engine_external_rules_enabled;  // enable loading YAML-based external rules
    std::string engine_external_rules_dir;  // directory containing external rule files

    // --- ClickHouse ---
    std::string clickhouse_host;
    uint16_t    clickhouse_port;      // HTTP port (default 8123)
    std::string clickhouse_db;        // database name
    std::string clickhouse_user;
    std::string clickhouse_password;  // loaded from env — never hard-coded

    // --- Engine ---
    std::string log_level;            // trace/debug/info/warn/error

    // Load all configuration from environment variables.
    // Throws std::runtime_error if a required variable is missing.
    static Config from_env() {
        Config c;
        c.kafka_brokers           = env_str("KAFKA_BROKERS",             "localhost:9092");
        c.kafka_group_id          = env_str("KAFKA_GROUP_ID",            "aegis-engine");
        c.kafka_topic_events      = env_str("KAFKA_TOPIC_EVENTS",        "siem.events");
        c.kafka_topic_alerts      = env_str("KAFKA_TOPIC_ALERTS",        "siem.alerts");
        c.kafka_topic_dlq         = env_str("KAFKA_TOPIC_EVENTS_DLQ",    "siem.events.dlq");
        c.kafka_poll_timeout_ms   = env_int("KAFKA_POLL_TIMEOUT_MS",     500);
        c.engine_batch_size       = env_int("ENGINE_BATCH_SIZE",         100);
        c.engine_batch_timeout_ms = env_int("ENGINE_BATCH_TIMEOUT_MS",   1000);
        c.engine_retry_max_attempts = env_int("ENGINE_RETRY_MAX_ATTEMPTS", 3);
        c.engine_retry_base_delay_ms = env_int("ENGINE_RETRY_BASE_DELAY_MS", 250);
        c.engine_metrics_interval_sec = env_int("ENGINE_METRICS_INTERVAL_SEC", 30);
        c.engine_external_rules_enabled = env_int("ENGINE_EXTERNAL_RULES_ENABLED", 1);
        c.engine_external_rules_dir = env_str("ENGINE_EXTERNAL_RULES_DIR", "rules/runtime");
        c.clickhouse_host         = env_str("CLICKHOUSE_HOST",           "localhost");
        c.clickhouse_port         = env_uint16("CLICKHOUSE_PORT",        8123);
        c.clickhouse_db           = env_str("CLICKHOUSE_DB",             "aegis");
        c.clickhouse_user         = env_str("CLICKHOUSE_USER",           "default");
        c.clickhouse_password     = env_str("CLICKHOUSE_PASSWORD",       "");
        c.log_level               = env_str("ENGINE_LOG_LEVEL",          "info");
        return c;
    }
};

}  // namespace aegis
