#pragma once

#include <atomic>
#include <memory>
#include <string>

#include "config.hpp"

namespace aegis::collector {

// Forward declare the signal handler
extern "C" void handle_sighup(int signum);

/// Manages dynamic config reloading via SIGHUP signal
class ConfigReloader {
public:
  explicit ConfigReloader(const std::string& config_path);
  
  /// Check if config has been updated and needs reload
  bool check_reload_signal();
  
  /// Reload config from file
  CollectorConfig reload_config();
  
  /// Register SIGHUP handler for this reloader
  static void register_global_handler(ConfigReloader* reloader);
  
  /// Get current config
  const CollectorConfig& get_config() const { return current_config_; }
  
  /// Get reload count
  int get_reload_count() const { return reload_count_; }
  
  /// Last reload timestamp
  std::string get_last_reload_time() const { return last_reload_time_; }

private:
  std::string config_path_;
  CollectorConfig current_config_;
  std::atomic<bool> reload_requested_{false};
  int reload_count_{0};
  std::string last_reload_time_;
  
  void set_reload_signal() { reload_requested_.store(true); }
  
  static ConfigReloader* g_instance_;
  friend void handle_sighup(int signum);
};

}  // namespace aegis::collector
