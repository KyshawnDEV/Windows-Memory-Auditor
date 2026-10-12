
#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>

#include "MemoryRegion.h"

/*
 * ScanResult.h
 *
 * Stores the outcome of virtual memory enumeration.
 *
 * A scan can be:
 *   - Complete
 *   - Partial
 *   - Failed
 *
 * Keeping the completion status separate from the
 * collected regions prevents incomplete scans from
 * being mistaken for successful audits.
 */

enum class ScanStatus
{
    Complete,
    Partial,
    Failed
};

struct ScanResult
{
    // Regions successfully collected.
    std::vector<MemoryRegion> regions;

    // Overall enumeration status.
    ScanStatus status = ScanStatus::Failed;

    // Windows error code if a query failed.
    DWORD errorCode = ERROR_SUCCESS;

    // Address at which enumeration stopped.
    std::uintptr_t failureAddress = 0;

    // Number of successful VirtualQueryEx() calls.
    std::size_t queriedRegions = 0;
};
