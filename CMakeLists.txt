
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor VERSION 0.4.1 LANGUAGES CXX)

# Use C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define source files.
add_executable(MemoryAuditor
    src/main.cpp
    src/Menu.cpp
    src/ProcessScanner.cpp
    src/ProcessEnumerator.cpp
    src/MemoryScanner.cpp
)

# Make header files accessible to all source files.
target_include_directories(MemoryAuditor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Enable compiler warnings.
if(MINGW)
    target_compile_options(MemoryAuditor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
