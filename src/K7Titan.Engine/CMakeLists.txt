cmake_minimum_required(VERSION 3.31)
project(K7TitanEngine VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(K7TitanEngine SHARED
  src/engine.cpp
  src/hasher.cpp
  src/pe_parser.cpp
  src/yara_wrapper.cpp
  src/heuristic.cpp
)

target_include_directories(K7TitanEngine PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(K7TitanEngine PRIVATE K7TITAN_ENGINE_EXPORTS _CRT_SECURE_NO_WARNINGS)
target_link_libraries(K7TitanEngine PRIVATE bcrypt.lib)

if(MSVC)
  target_compile_options(K7TitanEngine PRIVATE /W4 /permissive- /guard:cf)
  target_link_options(K7TitanEngine PRIVATE /GUARD:CF /CETCOMPAT)
endif()
