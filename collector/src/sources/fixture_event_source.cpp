#include "sources/fixture_event_source.hpp"

#include <fstream>
#include <stdexcept>

#include "sources/source_record_parser.hpp"

namespace aegis::collector {

FixtureEventSource::FixtureEventSource(const std::string& path) {
  std::ifstream input(path);
  if (!input.is_open()) {
    throw std::runtime_error("Cannot open fixture event file: " + path);
  }

  std::string line;
  std::size_t line_number = 0;
  while (std::getline(input, line)) {
    ++line_number;
    if (line.empty()) continue;

    SourceRecord parsed;
    std::string error;
    if (!try_parse_source_record_json(line, parsed, error)) {
      throw std::runtime_error(
        "Fixture parse error line " + std::to_string(line_number) + ": " + error);
    }
    records_.push_back(std::move(parsed));
  }
}

std::optional<SourceRecord> FixtureEventSource::next_event() {
  if (cursor_ >= records_.size()) {
    return std::nullopt;
  }
  return records_[cursor_++];
}

}  // namespace aegis::collector