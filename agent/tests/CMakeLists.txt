cmake_minimum_required(VERSION 3.10)
project(ebpf_monitor_tests CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

# Test: event_types
add_executable(test_event_types test_event_types.cpp)
add_test(NAME test_event_types COMMAND test_event_types)

# Test: event_sender (json_escape)
add_executable(test_event_sender test_event_sender.cpp)
add_test(NAME test_event_sender COMMAND test_event_sender)

# Test: logger
add_executable(test_logger test_logger.cpp ${CMAKE_CURRENT_SOURCE_DIR}/../src/logger.cpp)
target_link_libraries(test_logger pthread)
add_test(NAME test_logger COMMAND test_logger)

# Test: container_utils (requires mock /proc)
# Uncomment when container_utils is refactored to accept configurable proc path
# add_executable(test_container_utils test_container_utils.cpp
#     ${CMAKE_CURRENT_SOURCE_DIR}/../src/container_utils.cpp)
# target_link_libraries(test_container_utils pthread)
# add_test(NAME test_container_utils COMMAND test_container_utils)
