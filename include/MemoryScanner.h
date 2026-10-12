
#pragma once

#include <windows.h>
#include <vector>
#include <string>

#include "MemoryRegion.h"
#include "AuditMetrics.h"

/*
 * MemoryScanner.h
 *
 * Provides functions for inspecting the virtual
 * memory layout of a Windows process.
 *
 * Current Features:
 *   - Enumerate committed memory regions
 *   - Classify memory permissions
 *   - Identify writable/executable regions
 *   - Update audit metrics
 *
 * All operations are read-only.
 */

// Convert Windows memory protection flags to text.
std::string protectionToString(DWORD protection);

// Convert Windows memory types to text.
std::string memoryTypeToString(DWORD type);

// Determine whether a region is writable and executable.
bool isWritableExecutable(DWORD protection);

// Enumerate committed regions belonging to a process.
std::vector<MemoryRegion> enumerateMemoryRegions(
    HANDLE process
);

// Analyze and display the collected memory regions.
void analyzeMemoryRegions(
    const std::vector<MemoryRegion>& regions,
    AuditMetrics& metrics
);
