cmake_minimum_required(VERSION 3.25)

project(ujson LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (MSVC)
    add_compile_options(/WX /MP)
else()
    add_compile_options(-Werror)
endif()

add_library(ujson INTERFACE)
target_include_directories(ujson INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.4
)

FetchContent_Declare(
    rapidjson
    GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
    GIT_TAG v1.1.0
)

FetchContent_MakeAvailable(Catch2) 
FetchContent_Populate(rapidjson)

add_library(rapidjson INTERFACE)
target_include_directories(rapidjson INTERFACE ${rapidjson_SOURCE_DIR}/include)

file(GLOB TEST_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tests/*.cpp
)

file(GLOB BENCH_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/*.cpp
)

list(APPEND TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/catch_main.cpp
)

list(APPEND BENCH_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/catch_main.cpp
)

function(add_ujson_test_target target_name)

    add_executable(${target_name} ${TEST_SOURCES})

    target_link_libraries(${target_name}
        PRIVATE
            ujson
            Catch2::Catch2
            rapidjson
    )

    target_compile_definitions(${target_name} PRIVATE
        UJSON_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/data"
        _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
        $<$<NOT:$<CONFIG:Release>>:CATCH_CONFIG_DISABLE_BENCHMARKING>
    )

    include(Catch)
    catch_discover_tests(${target_name})

endfunction()

function(add_ujson_bench_target target_name)

    add_executable(${target_name} ${BENCH_SOURCES})

    target_link_libraries(${target_name}
        PRIVATE
            ujson
            Catch2::Catch2
            rapidjson
    )

    target_compile_definitions(${target_name} PRIVATE
        UJSON_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/data"
        _SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING
    )

endfunction()

add_ujson_test_target(ujson_tests_sse2)

if (MSVC)
    target_compile_options(ujson_tests_sse2 PRIVATE /arch:SSE2)
else()
    target_compile_options(ujson_tests_sse2 PRIVATE -msse2)
endif()

target_compile_definitions(ujson_tests_sse2 PRIVATE UJSON_SIMD_SSE2)

add_ujson_test_target(ujson_tests_avx2)

if (MSVC)
    target_compile_options(ujson_tests_avx2 PRIVATE /arch:AVX2)
else()
    target_compile_options(ujson_tests_avx2 PRIVATE -mavx2)
endif()

target_compile_definitions(ujson_tests_avx2 PRIVATE UJSON_SIMD_AVX2)

add_ujson_bench_target(ujson_bench_sse2)

if (MSVC)
    target_compile_options(ujson_bench_sse2 PRIVATE /arch:SSE2)
else()
    target_compile_options(ujson_bench_sse2 PRIVATE -msse2)
endif()

target_compile_definitions(ujson_bench_sse2 PRIVATE UJSON_SIMD_SSE2)

add_ujson_bench_target(ujson_bench_avx2)

if (MSVC)
    target_compile_options(ujson_bench_avx2 PRIVATE /arch:AVX2)
else()
    target_compile_options(ujson_bench_avx2 PRIVATE -mavx2)
endif()

target_compile_definitions(ujson_bench_avx2 PRIVATE UJSON_SIMD_AVX2)
