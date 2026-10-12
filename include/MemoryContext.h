#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "MemoryExposure.h"
#include "MemoryRegion.h"

/*
 * MemoryContext.h
 *
 * Stores v0.6 context independently of memory exposure rules.
 * A module association describes an observed mapping; it does
 * not verify code contents, signatures, or trustworthiness.
 *
 * Context lookup failures must not change memory scan status
 * or hide regions that were successfully enumerated.
 */
enum class ModuleSnapshotStatus
{
    NotQueried,
    Complete,
    Partial,
    Failed
};

enum class ModuleAssociationStatus
{
    NotApplicable,
    NotQueried,
    Available,
    NotObserved,
    Unavailable
};

enum class MappedFileStatus
{
    NotApplicable,
    NotQueried,
    Available,
    Unavailable
};

struct ModuleContext
{
    std::uintptr_t baseAddress = 0;
    std::uint64_t imageSize = 0;
    std::wstring name;
    std::wstring path;

    // Tool Help uses a fixed-size path buffer; do not assume it is unlimited.
    bool pathMayBeTruncated = false;
};

struct ModuleSnapshot
{
    std::vector<ModuleContext> modules;
    ModuleSnapshotStatus status = ModuleSnapshotStatus::NotQueried;
    DWORD errorCode = ERROR_SUCCESS;
};

struct AllocationContext
{
    std::uintptr_t allocationBase = 0;
    bool allocationBaseKnown = false;
    DWORD type = 0;

    /*
     * Only observed committed regions contribute to these values.
     * They are not the reservation size or a claim of complete coverage.
     * Region indices refer to the original scan vector without copying it.
     */
    std::vector<std::size_t> regionIndices;
    std::uint64_t committedBytes = 0;
    std::size_t executableRegions = 0;
    std::size_t writableExecutableRegions = 0;
    InvestigationPriority priority = InvestigationPriority::None;

    ModuleAssociationStatus moduleStatus = ModuleAssociationStatus::NotQueried;
    ModuleContext module;
    DWORD moduleErrorCode = ERROR_SUCCESS;

    MappedFileStatus mappedFileStatus = MappedFileStatus::NotQueried;
    std::wstring mappedFilePath;
    DWORD mappedFileErrorCode = ERROR_SUCCESS;
};

struct MemoryContext
{
    std::vector<AllocationContext> allocations;
    ModuleSnapshot moduleSnapshot;
};

// Group by AllocationBase; missing bases stay separate instead of merging at zero.
std::vector<AllocationContext> groupMemoryAllocations(const std::vector<MemoryRegion>& regions);

// Enumerate modules through Tool Help without reading target memory contents.
ModuleSnapshot enumerateProcessModules(HANDLE process);

// Associate only image regions whose allocation and observed ranges match a module.
void associateAllocationModules(std::vector<AllocationContext>& allocations,
    const std::vector<MemoryRegion>& regions, const ModuleSnapshot& snapshot);

// Collect module and mapped-file metadata using the existing query-only handle.
MemoryContext collectMemoryContext(HANDLE process, const std::vector<MemoryRegion>& regions);

// Display allocation details once, followed by their original region rows.
void displayAllocationContext(const AllocationContext& allocation);
void displayMemoryContextSummary(const MemoryContext& context);
