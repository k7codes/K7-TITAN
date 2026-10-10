cmake_minimum_required(VERSION 3.31)
project(K7TitanCLib VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(K7TitanCLib STATIC
  src/utils.c
  src/crc32.c
  src/fileio.c
  src/strings.c
)

target_include_directories(K7TitanCLib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
  target_compile_options(K7TitanCLib PRIVATE /W4 /permissive-)
endif()
