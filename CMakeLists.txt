cmake_minimum_required(VERSION 3.16)

# No Linux, clang do ambiente pode selecionar um GCC 14 sem libstdc++.
if(NOT CMAKE_CXX_COMPILER AND EXISTS "/usr/bin/g++")
    set(CMAKE_CXX_COMPILER "/usr/bin/g++")
endif()

project(tslab LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(tslab_native STATIC
    native/src/crc.cpp
    native/src/mapped_file.cpp
    native/src/psi.cpp
    native/src/engine.cpp
    native/src/tsduck.cpp
)
target_include_directories(tslab_native PUBLIC native/include)

set(PYBIND11_FINDPYTHON ON)
find_package(pybind11 CONFIG REQUIRED)

pybind11_add_module(_core native/src/bindings.cpp)
target_link_libraries(_core PRIVATE tslab_native)

install(TARGETS _core DESTINATION tslab)

# Cópia de desenvolvimento: python -m tslab com PYTHONPATH=src
add_custom_command(
    TARGET _core
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:_core> ${CMAKE_SOURCE_DIR}/src/tslab/
    COMMENT "Copiando _core para src/tslab"
)
