add_executable(aegis_collector_agent collector_main.cpp)
target_include_directories(aegis_collector_agent PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
