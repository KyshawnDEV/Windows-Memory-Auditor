
#pragma once

#include <windows.h>
#include <string>
#include <vector>

#include "AuditMetrics.h"
#include "MemoryRegion.h"
#include "MemoryExposure.h"
#include "MemoryContext.h"
#include "MemoryStatistics.h"
#include "ScanResult.h"

/*
 * MemoryScanner.h
 *
 * Declares functionality for enumerating, analyzing,
 * filtering, and displaying process memory regions.
 *
 * Version 0.5 adds:
 *   - Ordinary write and copy-on-write classification
 *   - Private, image, and mapped executable categories
 *   - Investigation priorities independent of access rights
 *
 * Version 0.6 adds:
 *   - Original allocation bases and allocation grouping
 *   - Observed module and mapped-file context
 */

// Controls which memory regions appear in the report.
enum class DisplayFilter
{
    All,
    Executable,
    WritableExecutable,
    Review
};

// Convert Windows memory attributes to readable text.
std::string protectionToString(DWORD protection);
std::string memoryTypeToString(DWORD type);

// Memory permission checks.
bool isExecutable(DWORD protection);
bool isWritable(DWORD protection);
bool isCopyOnWrite(DWORD protection);
bool isWritableExecutable(DWORD protection);

// Use one classification policy for totals, filters, and findings.
MemoryExposure classifyMemoryExposure(const MemoryRegion& region);
std::string exposureToString(ExposureCategory category);
std::string priorityToString(InvestigationPriority priority);
bool matchesDisplayFilter(const MemoryExposure& exposure, DisplayFilter filter);
AuditMetrics calculateAuditMetrics(const std::vector<MemoryRegion>& regions);

// Enumerate committed memory regions.
ScanResult enumerateMemoryRegions(HANDLE process);

// Calculate statistics from collected regions.
MemoryStatistics calculateMemoryStatistics(const std::vector<MemoryRegion>& regions);

// Display the memory region table using a selected filter.
void displayMemoryRegions(const std::vector<MemoryRegion>& regions, DisplayFilter filter,
    const MemoryContext* context = nullptr);

// Display scan status, memory statistics, and findings.
void displayAuditSummary( const ScanResult& result, const MemoryStatistics& statistics, const AuditMetrics& metrics);
