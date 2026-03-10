cmake_minimum_required(VERSION 3.20)
project(aegis_vanguard LANGUAGES C CXX)

option(AEGIS_BUILD_COLLECTOR "Build collector module" ON)
option(AEGIS_BUILD_ENGINE "Build engine module" ON)

if(AEGIS_BUILD_COLLECTOR)
  add_subdirectory(collector)
endif()

if(AEGIS_BUILD_ENGINE)
  add_subdirectory(engine)
endif()
