#pragma once

#include <string>
#include <string_view>

namespace aegis::collector::crypto {

std::string sha256_hex(std::string_view input);

}  // namespace aegis::collector::crypto