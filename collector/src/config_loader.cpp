#include "config_loader.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace aegis::collector {
namespace {

std::string trim_copy(std::string value) {
  const auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
  value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
  return value;
}

std::string unquote_copy(std::string value) {
  value = trim_copy(std::move(value));
  if (value.size() >= 2) {
    const char first = value.front();
    const char last = value.back();
    if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
      return value.substr(1, value.size() - 2);
    }
  }
  return value;
}

bool parse_bool_or_default(const std::string& value, bool fallback) {
  const std::string normalized = trim_copy(value);
  if (normalized == "true") return true;
  if (normalized == "false") return false;
  return fallback;
}

int parse_int_or_default(const std::string& value, int fallback) {
  try {
    return std::stoi(trim_copy(value));
  } catch (...) {
    return fallback;
  }
}

bool parse_key_value(const std::string& line, std::string& key, std::string& value) {
  const auto pos = line.find(':');
  if (pos == std::string::npos || pos == 0) return false;
  key = trim_copy(line.substr(0, pos));
  value = trim_copy(line.substr(pos + 1));
  return !key.empty();
}

std::filesystem::path resolve_relative_to_repo(const std::filesystem::path& relative_path) {
  std::error_code ec;
  std::filesystem::path cursor = std::filesystem::current_path(ec);
  if (ec) return relative_path;

  for (int depth = 0; depth <= 6; ++depth) {
    const std::filesystem::path candidate = cursor / relative_path;
    if (std::filesystem::exists(candidate, ec)) {
      return candidate;
    }
    if (!cursor.has_parent_path()) break;
    cursor = cursor.parent_path();
  }

  return relative_path;
}

std::string resolve_hostname_value(const std::string& value) {
  if (value == "${HOSTNAME}") {
    if (const char* env = std::getenv("HOSTNAME")) return env;
    if (const char* env = std::getenv("COMPUTERNAME")) return env;
  }
  return value;
}

}

CollectorConfig load_config_from_file(const std::string& path) {
  const std::filesystem::path resolved_path = std::filesystem::absolute(resolve_relative_to_repo(path));
  std::ifstream input(resolved_path);
  if (!input.is_open()) {
    throw std::runtime_error("Cannot open collector config: " + resolved_path.string());
  }

  CollectorConfig cfg;
  std::string current_section;
  std::string current_list;
  std::string line;

  while (std::getline(input, line)) {
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }

    if (trim_copy(line).empty()) continue;

    const std::size_t indent = line.find_first_not_of(' ');
    std::string trimmed = trim_copy(line);

    if (trimmed.rfind("- ", 0) == 0) {
      if (current_section == "kafka" && current_list == "brokers") {
        cfg.kafka.brokers.push_back(unquote_copy(trimmed.substr(2)));
      }
      continue;
    }

    std::string key;
    std::string value;
    if (!parse_key_value(trimmed, key, value)) continue;

    if (indent == 0) {
      current_list.clear();
      if (value.empty()) {
        current_section = key;
        continue;
      }

      current_section.clear();
      if (key == "agent_id") cfg.agent_id = unquote_copy(value);
      else if (key == "hostname") cfg.hostname = resolve_hostname_value(unquote_copy(value));
      continue;
    }

    if (indent == 2) {
      if (current_section == "kafka") {
        if (key == "brokers" && value.empty()) {
          current_list = "brokers";
        } else if (key == "topic") {
          current_list.clear();
          cfg.kafka.topic = unquote_copy(value);
        } else if (key == "retry_max_attempts") {
          cfg.kafka.retry_max_attempts = parse_int_or_default(value, cfg.kafka.retry_max_attempts);
        } else if (key == "retry_base_delay_ms") {
          cfg.kafka.retry_base_delay_ms = parse_int_or_default(value, cfg.kafka.retry_base_delay_ms);
        } else if (key == "flush_timeout_ms") {
          cfg.kafka.flush_timeout_ms = parse_int_or_default(value, cfg.kafka.flush_timeout_ms);
        }
      } else if (current_section == "collection") {
        current_list.clear();
        if (key == "process_events") cfg.collection.process_events = parse_bool_or_default(value, cfg.collection.process_events);
        else if (key == "network_events") cfg.collection.network_events = parse_bool_or_default(value, cfg.collection.network_events);
        else if (key == "file_events") cfg.collection.file_events = parse_bool_or_default(value, cfg.collection.file_events);
        else if (key == "auth_events") cfg.collection.auth_events = parse_bool_or_default(value, cfg.collection.auth_events);
      } else if (current_section == "runtime") {
        current_list.clear();
        if (key == "source") cfg.runtime.source_kind = unquote_copy(value);
        else if (key == "fixture_path") cfg.runtime.fixture_path = unquote_copy(value);
        else if (key == "ebpf_enabled") cfg.runtime.ebpf_enabled = parse_bool_or_default(value, cfg.runtime.ebpf_enabled);
        else if (key == "ebpf_input_path") cfg.runtime.ebpf_input_path = unquote_copy(value);
        else if (key == "ebpf_reader_command") cfg.runtime.ebpf_reader_command = unquote_copy(value);
        else if (key == "ebpf_follow") cfg.runtime.ebpf_follow = parse_bool_or_default(value, cfg.runtime.ebpf_follow);
        else if (key == "poll_interval_ms") cfg.runtime.poll_interval_ms = parse_int_or_default(value, cfg.runtime.poll_interval_ms);
        else if (key == "max_events") cfg.runtime.max_events = parse_int_or_default(value, cfg.runtime.max_events);
        else if (key == "dry_run") cfg.runtime.dry_run = parse_bool_or_default(value, cfg.runtime.dry_run);
        else if (key == "tenant_id") cfg.runtime.tenant_id = unquote_copy(value);
        else if (key == "log_level") cfg.runtime.log_level = unquote_copy(value);
      }
    }
  }

  if (cfg.kafka.brokers.empty()) {
    cfg.kafka.brokers.push_back("localhost:9092");
  }
  if (cfg.agent_id.empty()) {
    throw std::runtime_error("collector config requires agent_id");
  }
  if (cfg.hostname.empty()) {
    throw std::runtime_error("collector config requires hostname");
  }

  return cfg;
}

std::string resolve_default_config_path() {
  if (const char* env_path = std::getenv("AEGIS_COLLECTOR_CONFIG")) {
    return std::string(env_path);
  }
  return resolve_relative_to_repo("config/dev/collector.yaml").string();
}

}