#include "sources/source_record_parser.hpp"

#include <exception>

#include <nlohmann/json.hpp>

namespace aegis::collector {
namespace {

using json = nlohmann::json;

std::vector<std::string> read_flags(const json& doc) {
  std::vector<std::string> flags;
  if (!doc.contains("flags") || !doc.at("flags").is_array()) {
    return flags;
  }

  for (const auto& item : doc.at("flags")) {
    if (item.is_string()) {
      flags.push_back(item.get<std::string>());
    }
  }
  return flags;
}

}  // namespace

bool try_parse_source_record_json(const std::string& line, SourceRecord& out, std::string& error) {
  try {
    const json doc = json::parse(line);
    if (!doc.is_object()) {
      error = "JSON root must be an object";
      return false;
    }

    const std::string kind = doc.value("kind", "");
    if (kind.empty()) {
      error = "missing required field 'kind'";
      return false;
    }

    if (kind == "process_start") {
      out = ProcessStartRecord{
        .ts = doc.value("ts", ""),
        .process_guid = doc.value("process_guid", ""),
        .pid = doc.value("pid", 0u),
        .ppid = doc.value("ppid", 0u),
        .uid = doc.value("uid", 0u),
        .user_name = doc.value("user_name", ""),
        .name = doc.value("name", ""),
        .exe = doc.value("exe", ""),
        .cmdline = doc.value("cmdline", ""),
        .process_start_time = doc.value("process_start_time", ""),
      };
      return true;
    }

    if (kind == "network_connect") {
      out = NetworkConnectRecord{
        .ts = doc.value("ts", ""),
        .pid = doc.value("pid", 0u),
        .process_guid = doc.value("process_guid", ""),
        .protocol = doc.value("protocol", "tcp"),
        .src_ip = doc.value("src_ip", ""),
        .src_port = doc.value("src_port", 0u),
        .dst_ip = doc.value("dst_ip", ""),
        .dst_port = doc.value("dst_port", 0u),
        .direction = doc.value("direction", "outbound"),
      };
      return true;
    }

    if (kind == "file_open") {
      out = FileOpenRecord{
        .ts = doc.value("ts", ""),
        .pid = doc.value("pid", 0u),
        .process_guid = doc.value("process_guid", ""),
        .user_name = doc.value("user_name", ""),
        .path = doc.value("path", ""),
        .flags = read_flags(doc),
        .result = doc.value("result", "success"),
      };
      return true;
    }

    if (kind == "auth_failure") {
      out = AuthFailureRecord{
        .ts = doc.value("ts", ""),
        .user_name = doc.value("user_name", ""),
        .method = doc.value("method", ""),
        .src_ip = doc.value("src_ip", ""),
        .reason = doc.value("reason", ""),
      };
      return true;
    }

    error = "unsupported kind: " + kind;
    return false;
  } catch (const std::exception& ex) {
    error = std::string("JSON parse/convert error: ") + ex.what();
    return false;
  }
}

}