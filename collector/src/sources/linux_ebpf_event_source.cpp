#include "sources/linux_ebpf_event_source.hpp"

#include <algorithm>
#include <chrono>
#include <thread>

#include <spdlog/spdlog.h>

#include "sources/source_record_parser.hpp"

namespace aegis::collector {

LinuxEbpfEventSource::LinuxEbpfEventSource(const CollectorConfig& cfg)
    : input_path_(cfg.runtime.ebpf_input_path),
      reader_command_(cfg.runtime.ebpf_reader_command),
      follow_(cfg.runtime.ebpf_follow),
      poll_interval_ms_(std::max(10, cfg.runtime.poll_interval_ms)) {
#if defined(__linux__)
  if (!reader_command_.empty()) {
    spdlog::info("eBPF source command mode command='{}'", reader_command_);
  } else if (!input_path_.empty()) {
    spdlog::info("eBPF source file mode path='{}' follow={}", input_path_, follow_);
  } else {
    spdlog::warn("eBPF source has no command or input path configured");
    exhausted_ = true;
  }
#else
  spdlog::warn("eBPF source selected on a non-Linux platform; collector cannot attach kernel probes here");
  exhausted_ = true;
#endif
}

LinuxEbpfEventSource::~LinuxEbpfEventSource() {
#if defined(__linux__)
  if (command_pipe_) {
    ::pclose(command_pipe_);
    command_pipe_ = nullptr;
  }
#endif
}

std::optional<SourceRecord> LinuxEbpfEventSource::next_event() {
#if !defined(__linux__)
  exhausted_ = true;
  return std::nullopt;
#else
  if (exhausted_) {
    return std::nullopt;
  }

  while (!exhausted_) {
    std::string line;

    if (!reader_command_.empty()) {
      if (!command_pipe_) {
        command_pipe_ = ::popen(reader_command_.c_str(), "r");
        if (!command_pipe_) {
          spdlog::error("eBPF source failed to start command: {}", reader_command_);
          exhausted_ = true;
          return std::nullopt;
        }
      }

      char buffer[8192]{};
      if (!std::fgets(buffer, static_cast<int>(sizeof(buffer)), command_pipe_)) {
        exhausted_ = true;
        return std::nullopt;
      }

      line = buffer;
      while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
      }
    } else {
      if (!input_stream_.is_open()) {
        input_stream_.open(input_path_);
        if (!input_stream_.is_open()) {
          if (follow_) {
            if (!missing_input_logged_) {
              spdlog::warn("eBPF source waiting for input path: {}", input_path_);
              missing_input_logged_ = true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms_));
            continue;
          }

          spdlog::error("eBPF source failed to open input path: {}", input_path_);
          exhausted_ = true;
          return std::nullopt;
        }
        missing_input_logged_ = false;
      }

      if (!std::getline(input_stream_, line)) {
        if (follow_) {
          input_stream_.clear();
          std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms_));
          continue;
        }

        exhausted_ = true;
        return std::nullopt;
      }
    }

    if (line.empty()) {
      continue;
    }

    SourceRecord parsed;
    std::string error;
    if (try_parse_source_record_json(line, parsed, error)) {
      return parsed;
    }

    spdlog::warn("eBPF source dropped malformed line: {}", error);
  }

  exhausted_ = true;
  return std::nullopt;
#endif
}

}