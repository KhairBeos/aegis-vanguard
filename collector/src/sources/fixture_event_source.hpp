#pragma once

#include <optional>
#include <string>
#include <vector>

#include "sources/event_source.hpp"

namespace aegis::collector {

class FixtureEventSource final : public IEventSource {
public:
  explicit FixtureEventSource(const std::string& path);

  std::optional<SourceRecord> next_event() override;
  bool is_exhausted() const noexcept override { return cursor_ >= records_.size(); }
  std::string name() const override { return "fixture"; }

private:
  std::vector<SourceRecord> records_;
  std::size_t cursor_{0};
};

}