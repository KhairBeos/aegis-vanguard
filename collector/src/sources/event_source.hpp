#pragma once

#include <optional>
#include <string>

#include "../../include/types.hpp"

namespace aegis::collector {

class IEventSource {
public:
  virtual ~IEventSource() = default;

  virtual std::optional<SourceRecord> next_event() = 0;
  virtual bool is_exhausted() const noexcept = 0;
  virtual std::string name() const = 0;
};

} 