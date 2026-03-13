#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace aegis::collector {

struct KafkaConfig {
  std::vector<std::string> brokers;
  std::string topic{"siem.events"};
  int retry_max_attempts{3};
  int retry_base_delay_ms{250};
  int flush_timeout_ms{5000};
};

struct CollectionConfig {
  bool process_events{true};
  bool network_events{true};
  bool file_events{true};
  bool auth_events{true};
};

struct RuntimeConfig {
  std::string source_kind{"synthetic"};
  std::string fixture_path;
  bool ebpf_enabled{true};
  std::string ebpf_input_path{"/var/run/aegis/ebpf-events.jsonl"};
  std::string ebpf_reader_command;
  bool ebpf_follow{true};
  int poll_interval_ms{250};
  int max_events{5};
  bool dry_run{false};
  std::string tenant_id{"default"};
  std::string log_level{"info"};
};

struct CollectorConfig {
  std::string agent_id{"dev-collector-01"};
  std::string hostname{"localhost"};
  KafkaConfig kafka;
  CollectionConfig collection;
  RuntimeConfig runtime;
};

CollectorConfig load_config_from_file(const std::string& path);
std::string resolve_default_config_path();

}  // namespace aegis::collector