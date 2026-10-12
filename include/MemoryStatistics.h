
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

    // Total memory with writable permissions.
    std::uint64_t writableBytes = 0;

    // Committed bytes classified by memory type.
    std::uint64_t privateBytes = 0;
    std::uint64_t imageBytes = 0;
    std::uint64_t mappedBytes = 0;

    // Number of regions flagged for W+X review.
    std::size_t suspiciousRegions = 0;
};
