
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(MemoryAuditor main.cpp)

if(MINGW)
    target_compile_options(MemoryAuditor PRIVATE
        -Wall
        -Wextra
        -g
    )
endif()
