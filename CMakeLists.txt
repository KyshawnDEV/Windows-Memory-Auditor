
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor LANGUAGES CXX)

# Use C++17.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define the application's source files.
add_executable(MemoryAuditor
    src/main.cpp
    src/Menu.cpp
    src/ProcessScanner.cpp
)

# Tell the compiler where our header files are located.
target_include_directories(MemoryAuditor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Enable compiler warnings when using MinGW/GCC.
if(MINGW)
    target_compile_options(MemoryAuditor PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()
