#include <cassert>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

#include "config.hpp"
#include "config_loader.hpp"
#include "event_builder.hpp"
#include "sources/fixture_event_source.hpp"

using json = nlohmann::json;

namespace {

void test_config_loader() {
  const std::filesystem::path temp = std::filesystem::temp_directory_path() / "collector_test_config.yaml";
  std::ofstream out(temp);
  out << "agent_id: test-agent\n";
  out << "hostname: lab-host\n";
  out << "kafka:\n";
  out << "  brokers:\n";
  out << "    - kafka:29092\n";
  out << "  topic: siem.events\n";
  out << "collection:\n";
  out << "  process_events: true\n";
  out << "  network_events: false\n";
  out << "runtime:\n";
  out << "  source: fixture\n";
  out << "  fixture_path: sample.jsonl\n";
  out << "  ebpf_input_path: /tmp/aegis-ebpf.jsonl\n";
  out << "  ebpf_follow: true\n";
  out << "  max_events: 2\n";
  out.close();

  const aegis::collector::CollectorConfig cfg = aegis::collector::load_config_from_file(temp.string());
  assert(cfg.agent_id == "test-agent");
  assert(cfg.hostname == "lab-host");
  assert(cfg.kafka.brokers.size() == 1);
  assert(cfg.kafka.brokers.front() == "kafka:29092");
  assert(cfg.collection.process_events);
  assert(!cfg.collection.network_events);
  assert(cfg.runtime.source_kind == "fixture");
  assert(cfg.runtime.ebpf_input_path == "/tmp/aegis-ebpf.jsonl");
  assert(cfg.runtime.ebpf_follow);
  assert(cfg.runtime.max_events == 2);

  std::filesystem::remove(temp);
}

void test_event_builder() {
  aegis::collector::CollectorConfig cfg;
  cfg.agent_id = "collector-test-01";
  cfg.hostname = "host-a";
  cfg.runtime.tenant_id = "default";

  aegis::collector::CanonicalEventBuilder builder(cfg);
  const aegis::collector::ProcessStartRecord record{
    .ts = "2026-03-12T10:00:00Z",
    .process_guid = "fixed-guid",
    .pid = 1732,
    .ppid = 1120,
    .uid = 1000,
    .user_name = "alice",
    .name = "bash",
    .exe = "/usr/bin/bash",
    .cmdline = "bash -c whoami",
    .process_start_time = "2026-03-12T10:00:00Z",
  };

  const json doc = json::parse(builder.build(record));
  assert(doc.at("schema_version") == "v1.1");
  assert(doc.at("host") == "host-a");
  assert(doc.at("agent_id") == "collector-test-01");
  assert(doc.at("event_type") == "process_start");
  assert(doc.at("process_guid") == "fixed-guid");
  assert(doc.at("event").at("process").at("cmdline") == "bash -c whoami");

  const aegis::collector::ProcessStartRecord auto_guid_record{
    .ts = "2026-03-12T10:00:00Z",
    .process_guid = "",
    .pid = 1732,
    .ppid = 1120,
    .uid = 1000,
    .user_name = "alice",
    .name = "bash",
    .exe = "/usr/bin/bash",
    .cmdline = "bash -c whoami",
    .process_start_time = "2026-03-12T10:00:00Z",
  };

  const json generated_a = json::parse(builder.build(auto_guid_record));
  const json generated_b = json::parse(builder.build(auto_guid_record));

  const std::string guid_a = generated_a.at("process_guid").get<std::string>();
  const std::string guid_b = generated_b.at("process_guid").get<std::string>();

  assert(guid_a == guid_b);
  assert(guid_a.size() == 64);
  for (const unsigned char ch : guid_a) {
    assert(std::isxdigit(ch) != 0);
  }
}

void test_fixture_source() {
  const std::filesystem::path temp = std::filesystem::temp_directory_path() / "collector_fixture.jsonl";
  std::ofstream out(temp);
  out << "{\"kind\":\"auth_failure\",\"ts\":\"2026-03-12T10:00:00Z\",\"user_name\":\"root\",\"method\":\"ssh\",\"src_ip\":\"203.0.113.10\",\"reason\":\"invalid_password\"}\n";
  out.close();

  aegis::collector::FixtureEventSource source(temp.string());
  const auto record = source.next_event();
  assert(record.has_value());
  assert(aegis::collector::event_type_of(*record) == "auth_failure");
  assert(source.is_exhausted());

  const auto end = source.next_event();
  assert(!end.has_value());
  assert(source.is_exhausted());

  std::filesystem::remove(temp);
}

}  // namespace

int main() {
  test_config_loader();
  test_event_builder();
  test_fixture_source();
  return 0;
}