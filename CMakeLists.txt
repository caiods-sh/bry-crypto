cmake_minimum_required(VERSION 3.31)
project(DesafioBryCpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_compile_options(
    -Wall
    -Wextra
    -Werror
    -pedantic
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Release>:-O2>
)

add_link_options(
    $<$<CONFIG:Debug>:-fsanitize=address>
)

list(APPEND CMAKE_PREFIX_PATH "${CMAKE_BINARY_DIR}")

find_package(OpenSSL REQUIRED)
find_package(Poco REQUIRED COMPONENTS Net Util Foundation)
find_package(GTest REQUIRED)

add_subdirectory(src)
add_subdirectory(tests)