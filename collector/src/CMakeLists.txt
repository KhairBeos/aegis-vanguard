cmake_minimum_required(VERSION 3.20)
include(FetchContent)

FetchContent_Declare(
	json
	URL      https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
	URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
	DOWNLOAD_EXTRACT_TIMESTAMP ON
)
FetchContent_MakeAvailable(json)

FetchContent_Declare(
	spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog.git
	GIT_TAG        v1.13.0
	GIT_SHALLOW    TRUE
)
set(SPDLOG_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL        OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
	rdkafka
	GIT_REPOSITORY https://github.com/confluentinc/librdkafka.git
	GIT_TAG        v2.4.0
	GIT_SHALLOW    TRUE
)
set(RDKAFKA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RDKAFKA_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(WITH_SSL               OFF CACHE BOOL "" FORCE)
set(WITH_SASL              OFF CACHE BOOL "" FORCE)
set(WITH_SASL_SCRAM        OFF CACHE BOOL "" FORCE)
set(WITH_ZLIB              OFF CACHE BOOL "" FORCE)
set(WITH_ZSTD              OFF CACHE BOOL "" FORCE)
set(RDKAFKA_ENABLE_STATIC  ON  CACHE BOOL "" FORCE)

FetchContent_GetProperties(rdkafka)
if(NOT rdkafka_POPULATED)
	FetchContent_Populate(rdkafka)

	set(_rdkafka_cmakelists "${rdkafka_SOURCE_DIR}/CMakeLists.txt")
	if(EXISTS "${_rdkafka_cmakelists}")
		file(READ "${_rdkafka_cmakelists}" _rdkafka_cmake_contents)
		if(_rdkafka_cmake_contents MATCHES "cmake_minimum_required\\(VERSION[ \t]+3\\.2\\)")
			string(REGEX REPLACE
				"cmake_minimum_required\\(VERSION[ \t]+3\\.2\\)"
				"cmake_minimum_required(VERSION 3.10...3.31)"
				_rdkafka_cmake_contents
				"${_rdkafka_cmake_contents}")
			file(WRITE "${_rdkafka_cmakelists}" "${_rdkafka_cmake_contents}")
			message(STATUS "[collector] patched librdkafka cmake_minimum_required to 3.10...3.31")
		endif()
	endif()

	add_subdirectory("${rdkafka_SOURCE_DIR}" "${rdkafka_BINARY_DIR}")
endif()

set(COLLECTOR_SOURCES
	collector_main.cpp
	collector_runner.cpp
	config_loader.cpp
	config_reloader.cpp
	event_builder.cpp
	health_checker.cpp
	crypto/sha256.cpp
	kafka_event_producer.cpp
	sources/source_record_parser.cpp
	sources/fixture_event_source.cpp
	sources/linux_ebpf_event_source.cpp
	sources/synthetic_event_source.cpp
)

add_executable(aegis_collector_agent ${COLLECTOR_SOURCES})

target_compile_features(aegis_collector_agent PRIVATE cxx_std_20)
target_compile_options(aegis_collector_agent PRIVATE
	$<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic -Wno-unused-parameter>
	$<$<CXX_COMPILER_ID:MSVC>:/W4 /wd4100>
)

target_include_directories(aegis_collector_agent PRIVATE
	${CMAKE_CURRENT_SOURCE_DIR}/../include
	${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(aegis_collector_agent PRIVATE
	nlohmann_json::nlohmann_json
	spdlog::spdlog
	rdkafka++
)

if(WIN32 AND MINGW)
	get_filename_component(MINGW_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)

	add_custom_command(TARGET aegis_collector_agent POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			$<TARGET_FILE:rdkafka++>
			$<TARGET_FILE_DIR:aegis_collector_agent>
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			$<TARGET_FILE:rdkafka>
			$<TARGET_FILE_DIR:aegis_collector_agent>
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${MINGW_BIN_DIR}/libstdc++-6.dll"
			$<TARGET_FILE_DIR:aegis_collector_agent>
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${MINGW_BIN_DIR}/libgcc_s_seh-1.dll"
			$<TARGET_FILE_DIR:aegis_collector_agent>
		COMMAND ${CMAKE_COMMAND} -E copy_if_different
			"${MINGW_BIN_DIR}/libwinpthread-1.dll"
			$<TARGET_FILE_DIR:aegis_collector_agent>
		VERBATIM)
endif()
