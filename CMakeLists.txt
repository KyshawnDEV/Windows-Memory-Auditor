
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor VERSION 0.5.0 LANGUAGES CXX)

# The auditor uses native pointer-sized Windows query structures.
# A 32-bit scanner cannot represent the complete x64 address space.
if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Windows Memory Auditor requires a 64-bit Windows toolchain.")
endif()

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

# Register automated exposure checks separately from the manual target.
include(CTest)

if(BUILD_TESTING)
    add_executable(ExposureTests
        tests/ExposureTests.cpp
        src/MemoryScanner.cpp
    )

    target_include_directories(ExposureTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    if(MINGW)
        target_compile_options(ExposureTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME MemoryExposureAnalysis COMMAND ExposureTests)
    set_tests_properties(MemoryExposureAnalysis PROPERTIES TIMEOUT 30)

    # This fixture waits for console input and is not an automated test.
    add_executable(MemoryTest tests/MemoryTest.cpp)
endif()
