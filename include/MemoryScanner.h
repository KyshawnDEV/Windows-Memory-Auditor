
#pragma once

#include <windows.h>
#include <string>
#include <vector>

#include "AuditMetrics.h"
#include "MemoryRegion.h"
#include "MemoryStatistics.h"
#include "ScanResult.h"

/*
 * MemoryScanner.h
 *
 * Declares functionality for enumerating, analyzing,
 * filtering, and displaying process memory regions.
 *
 * Version 0.4 adds:
 *   - Scan completion tracking
 *   - Memory usage statistics
 *   - Memory region display filters
 *   - Expanded audit summaries
 */

// Controls which memory regions appear in the report.
enum class DisplayFilter
{
    All,
    Executable,
    Suspicious
};

// Convert Windows memory attributes to readable text.
std::string protectionToString(DWORD protection);
std::string memoryTypeToString(DWORD type);

// Memory permission checks.
bool isExecutable(DWORD protection);
bool isWritable(DWORD protection);
bool isWritableExecutable(DWORD protection);

// Enumerate committed memory regions.
ScanResult enumerateMemoryRegions(HANDLE process);

// Calculate statistics from collected regions.
MemoryStatistics calculateMemoryStatistics(const std::vector<MemoryRegion>& regions);

// Display the memory region table using a selected filter.
void displayMemoryRegions(const std::vector<MemoryRegion>& regions, DisplayFilter filter);

// Display scan status, memory statistics, and findings.
void displayAuditSummary( const ScanResult& result, const MemoryStatistics& statistics, const AuditMetrics& metrics);
