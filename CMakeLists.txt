
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(MemoryAuditor
    src/main.cpp
    src/Menu.cpp
    src/ProcessScanner.cpp
    src/ProcessEnumerator.cpp
)

target_include_directories(MemoryAuditor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MINGW)
    target_compile_options(MemoryAuditor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
