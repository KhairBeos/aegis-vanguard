#pragma once

#include <string>

#include "config.hpp"

namespace aegis::collector {

CollectorConfig load_config_from_file(const std::string& path);
std::string resolve_default_config_path();

}  // namespace aegis::collector