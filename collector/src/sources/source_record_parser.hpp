#pragma once

#include <string>

#include "types.hpp"

namespace aegis::collector {

bool try_parse_source_record_json(const std::string& line, SourceRecord& out, std::string& error);

}