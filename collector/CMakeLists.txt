cmake_minimum_required(VERSION 3.20)
project(aegis_collector LANGUAGES C CXX)

add_subdirectory(src)

if(BUILD_TESTING)
	add_subdirectory(tests)
endif()