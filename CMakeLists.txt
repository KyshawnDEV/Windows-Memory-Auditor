
cmake_minimum_required(VERSION 3.20)

project(MemoryAuditor VERSION 0.8.0 LANGUAGES CXX)

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
    src/MemoryContext.cpp
    src/ScanComparison.cpp
    src/AccessAssessment.cpp
)

# Make header files accessible to all source files.
target_include_directories(MemoryAuditor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# GetMappedFileNameW queries file association using the existing query handle.
target_link_libraries(MemoryAuditor PRIVATE psapi advapi32)

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
        src/MemoryContext.cpp
    )

    target_include_directories(ExposureTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ExposureTests PRIVATE psapi)

    if(MINGW)
        target_compile_options(ExposureTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME MemoryExposureAnalysis COMMAND ExposureTests)
    set_tests_properties(MemoryExposureAnalysis PROPERTIES TIMEOUT 30)

    # Context tests cover grouping, unavailable metadata, and live file mappings.
    add_executable(ContextTests
        tests/ContextTests.cpp
        src/MemoryScanner.cpp
        src/MemoryContext.cpp
    )

    target_include_directories(ContextTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ContextTests PRIVATE psapi)

    if(MINGW)
        target_compile_options(ContextTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME MemoryAllocationContext COMMAND ContextTests)
    set_tests_properties(MemoryAllocationContext PROPERTIES TIMEOUT 30)

    # Comparison tests include process identity, partial coverage, and live protection changes.
    add_executable(ComparisonTests
        tests/ComparisonTests.cpp
        src/ScanComparison.cpp
        src/MemoryScanner.cpp
        src/MemoryContext.cpp
    )
    target_include_directories(ComparisonTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ComparisonTests PRIVATE psapi)

    if(MINGW)
        target_compile_options(ComparisonTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME MemoryScanComparison COMMAND ComparisonTests)
    set_tests_properties(MemoryScanComparison PROPERTIES TIMEOUT 30)

    # Owned child fixtures validate fresh-handle grants, DACL denials, exit, and cleanup.
    add_executable(AccessAssessmentTests
        tests/AccessAssessmentTests.cpp
        src/AccessAssessment.cpp
        src/ScanComparison.cpp
        src/MemoryScanner.cpp
        src/MemoryContext.cpp
    )
    target_include_directories(AccessAssessmentTests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(AccessAssessmentTests PRIVATE psapi advapi32)

    if(MINGW)
        target_compile_options(AccessAssessmentTests PRIVATE -Wall -Wextra -Wpedantic)
    endif()

    add_test(NAME CurrentCallerAccessAssessment COMMAND AccessAssessmentTests)
    set_tests_properties(CurrentCallerAccessAssessment PROPERTIES TIMEOUT 30)

    # This fixture waits for console input and is not an automated test.
    add_executable(MemoryTest tests/MemoryTest.cpp)
endif()
