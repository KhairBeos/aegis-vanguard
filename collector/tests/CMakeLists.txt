add_executable(aegis_collector_tests
  collector_tests.cpp
  ../src/config_loader.cpp
  ../src/event_builder.cpp
  ../src/crypto/sha256.cpp
  ../src/sources/source_record_parser.cpp
  ../src/sources/fixture_event_source.cpp
)

target_compile_features(aegis_collector_tests PRIVATE cxx_std_20)
target_compile_options(aegis_collector_tests PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100>
)

target_include_directories(aegis_collector_tests PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

target_link_libraries(aegis_collector_tests PRIVATE
  nlohmann_json::nlohmann_json
  spdlog::spdlog
)

add_test(NAME aegis_collector_tests COMMAND aegis_collector_tests)