
#pragma once

#include <cstdint>
#include <cstddef>

/*
 * MemoryStatistics.h
 *
 * Stores statistics about committed memory regions
 * discovered during a process audit.
 *
 * Byte counters use uint64_t to accommodate large
 * virtual address spaces.
 */
struct MemoryStatistics
{
    // Total number of committed memory regions.
    std::size_t totalRegions = 0;

    // Total committed memory, in bytes.
    std::uint64_t committedBytes = 0;

    // Total memory with executable permissions.
    std::uint64_t executableBytes = 0;

    // Ordinary writable bytes; excludes copy-on-write protections.
    std::uint64_t writableBytes = 0;

    // Copy-on-write is a separate category, including executable COW.
    std::uint64_t copyOnWriteBytes = 0;
    std::uint64_t executableCopyOnWriteBytes = 0;
    std::uint64_t writableExecutableBytes = 0;

    // Executable bytes by reported type; private W+X is a subset.
    std::uint64_t privateExecutableBytes = 0;
    std::uint64_t privateWritableExecutableBytes = 0;
    std::uint64_t imageExecutableBytes = 0;
    std::uint64_t mappedExecutableBytes = 0;

    // Guarded bytes still contribute to their base permission totals.
    std::uint64_t guardedBytes = 0;

    // Committed bytes classified by memory type.
    std::uint64_t privateBytes = 0;
    std::uint64_t imageBytes = 0;
    std::uint64_t mappedBytes = 0;

    // Region counts describe configurations, not confirmed vulnerabilities.
    std::size_t writableExecutableRegions = 0;
    std::size_t executableCopyOnWriteRegions = 0;
    std::size_t privateExecutableRegions = 0;
    std::size_t privateWritableExecutableRegions = 0;
};
