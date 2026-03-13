#include "config_reloader.hpp"

#include <csignal>
#include <ctime>
#include <iomanip>
#include <sstream>

#include <spdlog/spdlog.h>

#include "config_loader.hpp"

namespace aegis::collector {

ConfigReloader* ConfigReloader::g_instance_ = nullptr;

// Global SIGHUP handler
extern "C" void handle_sighup(int signum) {
  (void)signum;
  if (ConfigReloader::g_instance_) {
    ConfigReloader::g_instance_->set_reload_signal();
  }
}

ConfigReloader::ConfigReloader(const std::string& config_path)
    : config_path_(config_path) {
  try {
    current_config_ = load_config_from_file(config_path);
    spdlog::info("ConfigReloader initialized: path={}", config_path);
  } catch (const std::exception& ex) {
    spdlog::error("ConfigReloader failed to load initial config: {}", ex.what());
    throw;
  }
}

void ConfigReloader::register_global_handler(ConfigReloader* reloader) {
  g_instance_ = reloader;
#ifdef _WIN32
  // SIGHUP not available on Windows - config reload via restart only
  spdlog::info("Config hot-reload (SIGHUP) not available on Windows platform");
#else
  // Unix/Linux: Register SIGHUP for config hot-reload
  std::signal(SIGHUP, handle_sighup);
  spdlog::info("SIGHUP handler registered for config hot-reload");
#endif
}

bool ConfigReloader::check_reload_signal() {
  if (reload_requested_.exchange(false)) {
    spdlog::info("Config reload signal received (SIGHUP)");
    return true;
  }
  return false;
}

CollectorConfig ConfigReloader::reload_config() {
  try {
    CollectorConfig new_config = load_config_from_file(config_path_);
    
    // Log what changed
    if (new_config.runtime.source_kind != current_config_.runtime.source_kind) {
      spdlog::warn("Config reload: source changed {} → {}",
                   current_config_.runtime.source_kind,
                   new_config.runtime.source_kind);
    }
    
    if (new_config.runtime.log_level != current_config_.runtime.log_level) {
      spdlog::warn("Config reload: log_level changed {} → {}",
                   current_config_.runtime.log_level,
                   new_config.runtime.log_level);
    }
    
    if (new_config.runtime.poll_interval_ms != current_config_.runtime.poll_interval_ms) {
      spdlog::info("Config reload: poll_interval_ms changed {} → {}",
                   current_config_.runtime.poll_interval_ms,
                   new_config.runtime.poll_interval_ms);
    }
    
    current_config_ = new_config;
    ++reload_count_;
    
    // Update timestamp
    auto now = std::time(nullptr);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    last_reload_time_ = oss.str();
    
    spdlog::info("Config reloaded successfully (reload_count={})", reload_count_);
    return current_config_;
    
  } catch (const std::exception& ex) {
    spdlog::error("Config reload failed: {}", ex.what());
    spdlog::warn("Keeping previous config");
    return current_config_;
  }
}

}  // namespace aegis::collector
