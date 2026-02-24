# CMakeList.txt : CMake project for ujson, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.10)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("ujson")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CATCH_BUILD_STATIC_LIBRARY OFF CACHE BOOL "" FORCE)

if (MSVC)
  add_compile_options(/WX)
else()
  add_compile_options(-Werror)
endif()

add_library(ujson INTERFACE)
target_include_directories(ujson INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

include(FetchContent)
if (POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.5.4
)
FetchContent_MakeAvailable(Catch2)

FetchContent_Declare(
  rapidjson
  GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
  GIT_TAG v1.1.0
)
FetchContent_GetProperties(rapidjson)
if (NOT rapidjson_POPULATED)
  FetchContent_Populate(rapidjson)
endif()

add_library(rapidjson INTERFACE)
target_include_directories(rapidjson INTERFACE "${rapidjson_SOURCE_DIR}/include")

enable_testing()
include(CTest)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ujson PROPERTY CXX_STANDARD 20)
endif()

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
list(APPEND TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/tests/catch_main.cpp")
add_executable(ujson_tests ${TEST_SOURCES})
target_link_libraries(ujson_tests PRIVATE ujson Catch2::Catch2 rapidjson)
target_compile_definitions(ujson_tests PRIVATE UJSON_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data")
if (MSVC)
  target_compile_options(ujson_tests PRIVATE /Zm2000 /bigobj /MP)
endif()
target_compile_definitions(ujson_tests PRIVATE _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING)
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET ujson_tests PROPERTY CXX_STANDARD 20)
endif()

add_executable(ujson_tests_avx2 ${TEST_SOURCES})
target_link_libraries(ujson_tests_avx2 PRIVATE ujson Catch2::Catch2 rapidjson)

target_compile_definitions(ujson_tests_avx2 PRIVATE
    UJSON_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data"
    _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
    RAPIDJSON_SSE42
)

if (MSVC)
  target_compile_options(ujson_tests_avx2 PRIVATE /Zm2000 /bigobj /MP /arch:AVX2)
else()
  target_compile_options(ujson_tests_avx2 PRIVATE -mavx2)
endif()

add_executable(ujson_tests_sse2 ${TEST_SOURCES})
target_link_libraries(ujson_tests_sse2 PRIVATE ujson Catch2::Catch2 rapidjson)

target_compile_definitions(ujson_tests_sse2 PRIVATE
    UJSON_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/data"
    _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
    RAPIDJSON_SSE2
)

if (MSVC)
  target_compile_options(ujson_tests_sse2 PRIVATE /Zm2000 /bigobj /MP /arch:SSE2)
else()
  target_compile_options(ujson_tests_sse2 PRIVATE -msse2)
endif()

include(Catch)
catch_discover_tests(ujson_tests)
catch_discover_tests(ujson_tests_avx2)
catch_discover_tests(ujson_tests_sse2)

add_custom_target(tests
  COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
  DEPENDS ujson_tests
  WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
