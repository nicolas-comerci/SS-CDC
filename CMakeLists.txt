cmake_minimum_required(VERSION 3.15)
project(ss_cdc LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC test-main.cpp xxhash.c)

add_executable(ss_cdc ${SRC})

target_compile_options(ss_cdc PRIVATE -march=native)

# Optional architecture override (e.g. for skylake-avx512)
option(USE_SKYLAKE_AVX512 "Enable -march=skylake-avx512" OFF)

if(USE_SKYLAKE_AVX512)
    target_compile_options(ss_cdc PRIVATE -march=skylake-avx512)
endif()
