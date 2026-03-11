##############################################################################
# engine/src/CMakeLists.txt
# Builds the aegis_engine executable and fetches all third-party dependencies.
##############################################################################

cmake_minimum_required(VERSION 3.20)
include(FetchContent)

##############################################################################
# Third-party dependencies
##############################################################################

# --- nlohmann/json (header-only) -------------------------------------------
FetchContent_Declare(
	json
	URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
	URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
	DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(json)

# --- spdlog (header-only, compile-time format) ------------------------------
FetchContent_Declare(
	spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog.git
	GIT_TAG        v1.13.0
	GIT_SHALLOW    TRUE
)
set(SPDLOG_BUILD_EXAMPLES  OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS     OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL         OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(spdlog)

# --- cpp-httplib (single-header HTTP client for ClickHouse HTTP API) --------
FetchContent_Declare(
	httplib
	GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
	GIT_TAG        v0.15.3
	GIT_SHALLOW    TRUE
)
set(HTTPLIB_REQUIRE_OPENSSL  OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(httplib)

# --- librdkafka (Kafka C++ client) ------------------------------------------
FetchContent_Declare(
	rdkafka
	GIT_REPOSITORY https://github.com/confluentinc/librdkafka.git
	GIT_TAG        v2.4.0
	GIT_SHALLOW    TRUE
)
set(RDKAFKA_BUILD_EXAMPLES    OFF CACHE BOOL "" FORCE)
set(RDKAFKA_BUILD_TESTS       OFF CACHE BOOL "" FORCE)
# Disable optional system library dependencies for portable dev builds.
# For production, enable WITH_SSL=ON and WITH_SASL_SCRAM=ON and link OpenSSL.
set(WITH_SSL                  OFF CACHE BOOL "" FORCE)
set(WITH_SASL                 OFF CACHE BOOL "" FORCE)
set(WITH_SASL_SCRAM           OFF CACHE BOOL "" FORCE)
set(WITH_ZLIB                 OFF CACHE BOOL "" FORCE)
set(WITH_ZSTD                 OFF CACHE BOOL "" FORCE)
set(RDKAFKA_ENABLE_STATIC     ON  CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(rdkafka)

##############################################################################
# aegis_engine target
##############################################################################

set(ENGINE_SOURCES
	engine_main.cpp
	pipeline/kafka_producer.cpp
	pipeline/kafka_consumer.cpp
	pipeline/event_validator.cpp
	pipeline/clickhouse_writer.cpp
	pipeline/dlq_handler.cpp
	detection/rule_engine.cpp
	detection/alert_publisher.cpp
)

add_executable(aegis_engine ${ENGINE_SOURCES})

# Platform-specific warning flags
target_compile_options(aegis_engine PRIVATE
	$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
	$<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100>
)

# Include directories:
#   - engine/include/      shared headers (config, types, logger)
#   - engine/src/          so components can include "pipeline/..." and "detection/..."
target_include_directories(aegis_engine PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/../include
	${CMAKE_CURRENT_SOURCE_DIR}
)

# Link all dependencies
target_link_libraries(aegis_engine PRIVATE
	nlohmann_json::nlohmann_json
	spdlog::spdlog
	httplib::httplib
	rdkafka++                  # C++ wrapper (links rdkafka C lib transitively)
)

if (BUILD_TESTING)
	add_executable(aegis_engine_tests
		tests/engine_detection_tests.cpp
		pipeline/event_validator.cpp
		detection/rule_engine.cpp
	)

	target_compile_options(aegis_engine_tests PRIVATE
		$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
		$<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100>
	)

	target_include_directories(aegis_engine_tests PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/../include
		${CMAKE_CURRENT_SOURCE_DIR}
	)

	target_link_libraries(aegis_engine_tests PRIVATE
		nlohmann_json::nlohmann_json
		spdlog::spdlog
	)

	add_test(NAME aegis_engine_tests COMMAND aegis_engine_tests)
endif()

# Package runtime DLLs next to the executable for MinGW-based Windows builds.
# Without this, the built exe exits with STATUS_DLL_NOT_FOUND unless the caller
# happens to have the compiler runtime and librdkafka DLLs on PATH.
if (WIN32 AND MINGW)
    get_filename_component(MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)

    add_custom_command(TARGET aegis_engine POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:rdkafka++>
            $<TARGET_FILE_DIR:aegis_engine>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:rdkafka>
            $<TARGET_FILE_DIR:aegis_engine>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MINGW_BIN_DIR}/libstdc++-6.dll"
            $<TARGET_FILE_DIR:aegis_engine>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MINGW_BIN_DIR}/libgcc_s_seh-1.dll"
            $<TARGET_FILE_DIR:aegis_engine>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MINGW_BIN_DIR}/libwinpthread-1.dll"
            $<TARGET_FILE_DIR:aegis_engine>
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MINGW_BIN_DIR}/zlib1__.dll"
            $<TARGET_FILE_DIR:aegis_engine>
        VERBATIM)
endif()

# Export compile_commands.json for clangd / IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON PARENT_SCOPE)

message(STATUS "[engine] aegis_engine sources: ${ENGINE_SOURCES}")
