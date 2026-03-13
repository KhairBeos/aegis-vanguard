#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace aegis::collector {

struct ProcessStartRecord {
  std::string ts;
  std::string process_guid;
  uint32_t pid{0};
  uint32_t ppid{0};
  uint32_t uid{0};
  std::string user_name;
  std::string name;
  std::string exe;
  std::string cmdline;
  std::string process_start_time;
};

struct NetworkConnectRecord {
  std::string ts;
  uint32_t pid{0};
  std::string process_guid;
  std::string protocol{"tcp"};
  std::string src_ip;
  uint32_t src_port{0};
  std::string dst_ip;
  uint32_t dst_port{0};
  std::string direction{"outbound"};
};

struct FileOpenRecord {
  std::string ts;
  uint32_t pid{0};
  std::string process_guid;
  std::string user_name;
  std::string path;
  std::vector<std::string> flags;
  std::string result{"success"};
};

struct AuthFailureRecord {
  std::string ts;
  std::string user_name;
  std::string method;
  std::string src_ip;
  std::string reason;
};

using SourceRecord = std::variant<ProcessStartRecord, NetworkConnectRecord, FileOpenRecord, AuthFailureRecord>;

inline std::string event_type_of(const SourceRecord& record) {
  if (std::holds_alternative<ProcessStartRecord>(record)) return "process_start";
  if (std::holds_alternative<NetworkConnectRecord>(record)) return "network_connect";
  if (std::holds_alternative<FileOpenRecord>(record)) return "file_open";
  return "auth_failure";
}

}  // namespace aegis::collector