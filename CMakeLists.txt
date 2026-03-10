cmake_minimum_required(VERSION 3.20)
project(aegis_vanguard LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(AEGIS_BUILD_COLLECTOR "Build collector module" ON)
option(AEGIS_BUILD_ENGINE "Build engine module" ON)
option(AEGIS_ENABLE_TESTING "Enable CTest support" ON)

if(AEGIS_ENABLE_TESTING)
  include(CTest)
  enable_testing()
endif()

message(STATUS "AEGIS_BUILD_COLLECTOR=${AEGIS_BUILD_COLLECTOR}")
message(STATUS "AEGIS_BUILD_ENGINE=${AEGIS_BUILD_ENGINE}")
message(STATUS "AEGIS_ENABLE_TESTING=${AEGIS_ENABLE_TESTING}")

if(AEGIS_BUILD_COLLECTOR)
  add_subdirectory(collector)
endif()

if(AEGIS_BUILD_ENGINE)
  add_subdirectory(engine)
endif()
