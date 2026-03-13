#pragma once

#include <memory>
#include <string>

#include "config.hpp"
#include "config_reloader.hpp"
#include "health_checker.hpp"

namespace aegis::collector {

class CollectorRunner {
public:
  CollectorRunner(CollectorConfig cfg, std::string config_path);

  int run();

private:
  CollectorConfig cfg_;
  std::string config_path_;
  std::unique_ptr<ConfigReloader> config_reloader_;
  std::unique_ptr<HealthChecker> health_checker_;
};

}  // namespace aegis::collector