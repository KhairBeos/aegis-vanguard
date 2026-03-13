#pragma once

#include <optional>
#include <string>
#include <vector>

#include "config.hpp"
#include "sources/event_source.hpp"

namespace aegis::collector {

class SyntheticEventSource final : public IEventSource {
public:
  explicit SyntheticEventSource(const CollectorConfig& cfg);

  std::optional<SourceRecord> next_event() override;
  bool is_exhausted() const noexcept override { return cursor_ >= records_.size(); }
  std::string name() const override { return "synthetic"; }

private:
  std::vector<SourceRecord> records_;
  std::size_t cursor_{0};
};

}  // namespace aegis::collector