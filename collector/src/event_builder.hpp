#pragma once

#include <string>

#include "config.hpp"
#include "health_checker.hpp"
#include "types.hpp"

namespace aegis::collector {

class CanonicalEventBuilder {
public:
  explicit CanonicalEventBuilder(const CollectorConfig& cfg) : cfg_(cfg) {}

  std::string build(const SourceRecord& record) const;
  std::string build_health_event(const HealthStatus& status) const;

private:
  CollectorConfig cfg_;
};

bool is_collection_enabled(const CollectorConfig& cfg, const SourceRecord& record);

}  // namespace aegis::collector