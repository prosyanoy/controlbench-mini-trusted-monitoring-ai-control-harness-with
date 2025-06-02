cmake_minimum_required(VERSION 3.16)
project(controlbench_sandbox LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "The ControlBench sandbox requires Linux (seccomp, Landlock).")
endif()

option(CB_BUILD_TESTS "Build the GoogleTest suite" ON)

find_package(Threads REQUIRED)

add_library(cbsandbox STATIC
  src/json.cpp
  src/sandbox.cpp
  src/seccomp_filter.cpp
  src/landlock.cpp
  src/thread_pool.cpp)
target_include_directories(cbsandbox PUBLIC include PRIVATE src)
target_link_libraries(cbsandbox PUBLIC Threads::Threads)
target_compile_options(cbsandbox PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(cb_sandbox src/main.cpp)
target_link_libraries(cb_sandbox PRIVATE cbsandbox)
target_compile_options(cb_sandbox PRIVATE -Wall -Wextra)

if(CB_BUILD_TESTS)
  enable_testing()
  find_package(GTest QUIET)
  if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(googletest
      URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()
  add_executable(sandbox_tests tests/json_test.cpp tests/thread_pool_test.cpp tests/sandbox_test.cpp)
  target_link_libraries(sandbox_tests PRIVATE cbsandbox GTest::gtest_main)
  target_include_directories(sandbox_tests PRIVATE src)
  include(GoogleTest)
  gtest_discover_tests(sandbox_tests DISCOVERY_TIMEOUT 60)
endif()
