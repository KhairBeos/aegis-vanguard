#pragma once
// engine/include/logger.hpp — Thin spdlog initialiser and convenience macros.
// All engine components call spdlog::info/warn/error directly after init_logger().

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <memory>
#include <string>

namespace aegis {

inline void init_logger(const std::string& level_str = "info") {
    // Create a color console logger as the global default.
    auto logger = spdlog::stdout_color_mt("aegis");
    logger->set_pattern("[%Y-%m-%dT%H:%M:%S.%e] [%^%l%$] %v");

    // Map level string → spdlog enum.
    spdlog::level::level_enum level = spdlog::level::info;
    if (level_str == "trace")       level = spdlog::level::trace;
    else if (level_str == "debug")  level = spdlog::level::debug;
    else if (level_str == "warn")   level = spdlog::level::warn;
    else if (level_str == "error")  level = spdlog::level::err;

    logger->set_level(level);
    spdlog::set_default_logger(logger);
    spdlog::set_level(level);
}

}  // namespace aegis
