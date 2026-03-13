#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>

#include <spdlog/spdlog.h>

#include "collector_runner.hpp"
#include "config.hpp"
#include "config_loader.hpp"

namespace {

void init_logger(const std::string& level) {
  spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
  if (level == "trace") {
    spdlog::set_level(spdlog::level::trace);
  } else if (level == "debug") {
    spdlog::set_level(spdlog::level::debug);
  } else if (level == "warn") {
    spdlog::set_level(spdlog::level::warn);
  } else if (level == "error") {
    spdlog::set_level(spdlog::level::err);
  } else {
    spdlog::set_level(spdlog::level::info);
  }
}

}

int main(int argc, char** argv) {
  try {
    const std::string config_path = (argc > 1)
      ? std::string(argv[1])
      : aegis::collector::resolve_default_config_path();

    const aegis::collector::CollectorConfig cfg =
      aegis::collector::load_config_from_file(config_path);

    init_logger(cfg.runtime.log_level);
    spdlog::info("Collector config={} source={} dry_run={} topic={} brokers={}",
                 config_path,
                 cfg.runtime.source_kind,
                 cfg.runtime.dry_run,
                 cfg.kafka.topic,
                 cfg.kafka.brokers.empty() ? std::string("<none>") : cfg.kafka.brokers.front());

    aegis::collector::CollectorRunner runner(cfg, config_path);
    return runner.run();
  } catch (const std::exception& ex) {
    std::cerr << "Collector startup error: " << ex.what() << std::endl;
    return EXIT_FAILURE;
  }
}
