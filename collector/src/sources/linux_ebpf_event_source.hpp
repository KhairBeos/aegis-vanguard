#pragma once

#include <fstream>
#include <optional>
#include <string>
#if defined(__linux__)
#include <cstdio>
#endif

#include "../../include/config.hpp"
#include "sources/event_source.hpp"

namespace aegis::collector {

class LinuxEbpfEventSource final : public IEventSource {
public:
  explicit LinuxEbpfEventSource(const CollectorConfig& cfg);
  ~LinuxEbpfEventSource() override;

  std::optional<SourceRecord> next_event() override;
  bool is_exhausted() const noexcept override { return exhausted_; }
  std::string name() const override { return "ebpf"; }

private:
  std::string input_path_;
  std::string reader_command_;
  bool follow_{true};
  int poll_interval_ms_{250};

#if defined(__linux__)
  std::FILE* command_pipe_{nullptr};
#endif
  std::ifstream input_stream_;
  bool missing_input_logged_{false};
  bool exhausted_{false};
};

}