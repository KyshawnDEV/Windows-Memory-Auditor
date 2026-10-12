#include "MemoryContext.h"
#include "MemoryScanner.h"
#include "WindowsHandle.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <utility>

/*
 * MemoryContext.cpp
 *
 * Adds allocation grouping, loader module associations, and
 * mapped-file paths to the existing memory exposure report.
 *
 * Windows APIs:
 *   GetProcessId()
 *   CreateToolhelp32Snapshot()
 *   Module32FirstW() / Module32NextW()
 *   GetMappedFileNameW()
 *
 * No target memory contents are read or modified. Context is
 * observed after the memory walk and may change independently.
 */

// ============================================================
// ALLOCATION GROUPING
// ============================================================

std::vector<AllocationContext> groupMemoryAllocations(const std::vector<MemoryRegion>& regions)
{
    std::vector<AllocationContext> allocations;

    /*
     * The key records whether AllocationBase is known.
     * A missing base falls back to the individual region index,
     * preventing unrelated records from being merged at address zero.
     * The ordered map is only an index; output keeps first-observed order.
     */
    std::map<std::pair<bool, std::uintptr_t>, std::size_t> allocationIndices;

    for (std::size_t index = 0; index < regions.size(); index++)
    {
        const MemoryRegion& region = regions[index];

        if (region.state != MEM_COMMIT)
            continue;

        bool baseKnown = region.allocationBase != 0;
        auto key = std::make_pair(baseKnown,
            baseKnown ? region.allocationBase : static_cast<std::uintptr_t>(index));
        auto found = allocationIndices.find(key);

        if (found == allocationIndices.end())
        {
            AllocationContext allocation{};
            allocation.allocationBase = region.allocationBase;
            allocation.allocationBaseKnown = baseKnown;
            allocation.type = region.type;
            allocations.push_back(allocation);
            found = allocationIndices.emplace(key, allocations.size() - 1).first;
        }

        AllocationContext& allocation = allocations[found->second];
        allocation.regionIndices.push_back(index);
        allocation.committedBytes += static_cast<std::uint64_t>(region.regionSize);

        // Conflicting reported types must not become a confident module association.
        if (allocation.type != region.type)
            allocation.type = 0;

        MemoryExposure exposure = classifyMemoryExposure(region);
        allocation.executableRegions += exposure.executable;
        allocation.writableExecutableRegions += exposure.executable && exposure.writable;

        // The allocation priority is its highest observed region priority.
        if (exposure.priority > allocation.priority)
            allocation.priority = exposure.priority;

        if (allocation.type == MEM_PRIVATE)
        {
            allocation.moduleStatus = ModuleAssociationStatus::NotApplicable;
            allocation.mappedFileStatus = MappedFileStatus::NotApplicable;
        }
        else
        {
            allocation.moduleStatus = allocation.type == MEM_IMAGE
                ? ModuleAssociationStatus::NotQueried
                : ModuleAssociationStatus::NotApplicable;
            allocation.mappedFileStatus = MappedFileStatus::NotQueried;
        }
    }

    return allocations;
}


// ============================================================
// MODULE SNAPSHOT
// ============================================================

ModuleSnapshot enumerateProcessModules(HANDLE process)
{
    ModuleSnapshot result{};

    if (process == nullptr || process == INVALID_HANDLE_VALUE)
    {
        result.status = ModuleSnapshotStatus::Failed;
        result.errorCode = ERROR_INVALID_HANDLE;
        return result;
    }

    DWORD pid = GetProcessId(process);

    if (pid == 0)
    {
        result.status = ModuleSnapshotStatus::Failed;
        result.errorCode = GetLastError();
        return result;
    }

    /*
     * Resolve the PID from the opened handle so a caller cannot
     * accidentally pair memory from one process with another PID.
     * Both module flags cover native and WOW64 loader lists.
     *
     * Loader changes can produce ERROR_BAD_LENGTH. Retry a bounded
     * number of times, then report missing context without blocking
     * the entire audit indefinitely.
     */
    HANDLE snapshot = INVALID_HANDLE_VALUE;

    for (unsigned int attempt = 0; attempt < 3; attempt++)
    {
        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

        if (snapshot != INVALID_HANDLE_VALUE)
            break;

        result.errorCode = GetLastError();

        if (result.errorCode != ERROR_BAD_LENGTH)
            break;
    }

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        result.status = ModuleSnapshotStatus::Failed;
        return result;
    }

    WindowsHandle owner(snapshot);
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot, &entry))
    {
        result.errorCode = GetLastError();
        result.status = result.errorCode == ERROR_NO_MORE_FILES
            ? ModuleSnapshotStatus::Complete : ModuleSnapshotStatus::Failed;

        if (result.status == ModuleSnapshotStatus::Complete)
            result.errorCode = ERROR_SUCCESS;

        return result;
    }

    do
    {
        ModuleContext module{};
        module.baseAddress = reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
        module.imageSize = entry.modBaseSize;
        module.name = entry.szModule;
        module.path = entry.szExePath;
        module.pathMayBeTruncated = module.path.size() >= MAX_PATH - 1;
        result.modules.push_back(module);
    } while (Module32NextW(snapshot, &entry));

    DWORD errorCode = GetLastError();
    result.status = errorCode == ERROR_NO_MORE_FILES
        ? ModuleSnapshotStatus::Complete : ModuleSnapshotStatus::Partial;
    result.errorCode = errorCode == ERROR_NO_MORE_FILES ? ERROR_SUCCESS : errorCode;
    return result;
}


// ============================================================
// MODULE ASSOCIATION
// ============================================================

void associateAllocationModules(std::vector<AllocationContext>& allocations,
    const std::vector<MemoryRegion>& regions, const ModuleSnapshot& snapshot)
{
    for (AllocationContext& allocation : allocations)
    {
        allocation.module = ModuleContext{};
        allocation.moduleErrorCode = ERROR_SUCCESS;

        if (allocation.type != MEM_IMAGE)
        {
            allocation.moduleStatus = ModuleAssociationStatus::NotApplicable;
            continue;
        }

        if (!allocation.allocationBaseKnown)
        {
            allocation.moduleStatus = ModuleAssociationStatus::Unavailable;
            allocation.moduleErrorCode = ERROR_INVALID_DATA;
            continue;
        }

        allocation.moduleStatus = snapshot.status == ModuleSnapshotStatus::Complete
            ? ModuleAssociationStatus::NotObserved
            : ModuleAssociationStatus::Unavailable;
        allocation.moduleErrorCode = snapshot.errorCode;

        if (snapshot.status == ModuleSnapshotStatus::NotQueried)
            allocation.moduleStatus = ModuleAssociationStatus::NotQueried;

        for (const ModuleContext& module : snapshot.modules)
        {
            if (module.baseAddress != allocation.allocationBase || module.imageSize == 0)
                continue;

            /*
             * A matching base alone is not enough. Every observed region
             * must fit within the module's recorded image range.
             * Offset subtraction avoids overflowing base + imageSize.
             *
             * A match is an association between two observations, not
             * proof that the loader mapping or its contents remained unchanged.
             */
            bool matches = !allocation.regionIndices.empty();

            for (std::size_t index : allocation.regionIndices)
            {
                if (index >= regions.size())
                {
                    matches = false;
                    break;
                }

                const MemoryRegion& region = regions[index];

                if (region.state != MEM_COMMIT || region.type != MEM_IMAGE ||
                    region.allocationBase != module.baseAddress ||
                    region.baseAddress < module.baseAddress)
                {
                    matches = false;
                    break;
                }

                std::uint64_t offset = region.baseAddress - module.baseAddress;

                if (offset >= module.imageSize || region.regionSize > module.imageSize - offset)
                {
                    matches = false;
                    break;
                }
            }

            if (matches)
            {
                allocation.module = module;
                allocation.moduleStatus = ModuleAssociationStatus::Available;
                allocation.moduleErrorCode = ERROR_SUCCESS;
                break;
            }
        }
    }
}


// ============================================================
// MAPPED FILE CONTEXT
// ============================================================

MemoryContext collectMemoryContext(HANDLE process, const std::vector<MemoryRegion>& regions)
{
    MemoryContext context{};
    context.allocations = groupMemoryAllocations(regions);

    // An empty or failed memory scan has no allocation context to enrich.
    if (context.allocations.empty())
        return context;

    context.moduleSnapshot = enumerateProcessModules(process);
    associateAllocationModules(context.allocations, regions, context.moduleSnapshot);

    for (AllocationContext& allocation : context.allocations)
    {
        if (allocation.type != MEM_IMAGE && allocation.type != MEM_MAPPED)
        {
            allocation.mappedFileStatus = MappedFileStatus::NotApplicable;
            continue;
        }

        /*
         * Query one observed committed address per allocation, rather
         * than a potentially reserved allocation base. A device path
         * is retained exactly as returned; no drive-letter guess is made.
         *
         * Paging-file-backed views may have no file name. A failure
         * therefore means unavailable context, not evidence of injection.
         */
        const MemoryRegion& region = regions[allocation.regionIndices.front()];
        allocation.mappedFileStatus = MappedFileStatus::Unavailable;

        for (DWORD capacity = 512; capacity <= 32768; capacity *= 2)
        {
            std::vector<wchar_t> buffer(capacity, L'\0');
            SetLastError(ERROR_SUCCESS);
            DWORD length = GetMappedFileNameW(process,
                reinterpret_cast<LPVOID>(region.baseAddress), buffer.data(), capacity);
            DWORD errorCode = GetLastError();

            if (length == 0)
            {
                allocation.mappedFileErrorCode = errorCode;
                break;
            }

            // A full buffer may be truncated; never display it as a complete path.
            if (length >= capacity || errorCode == ERROR_INSUFFICIENT_BUFFER)
            {
                allocation.mappedFileErrorCode = ERROR_INSUFFICIENT_BUFFER;
                continue;
            }

            allocation.mappedFilePath.assign(buffer.data(), length);
            allocation.mappedFileStatus = MappedFileStatus::Available;
            allocation.mappedFileErrorCode = ERROR_SUCCESS;
            break;
        }
    }

    return context;
}


// ============================================================
// CONTEXT DISPLAY
// ============================================================

/*
 * contextTextToString()
 *
 * Paths are stored as Unicode. Escape non-ASCII UTF-16 units
 * and control characters for this narrow console interface.
 * This preserves their spelling without changing the user's
 * console code page or allowing a newline in a path to create rows.
 */
static std::string contextTextToString(const std::wstring& value)
{
    std::ostringstream output;

    for (wchar_t character : value)
    {
        if (character >= L' ' && character <= L'~')
            output << static_cast<char>(character);
        else
            output << "\\u" << std::hex << std::uppercase << std::setfill('0')
                   << std::setw(4) << static_cast<unsigned int>(character);
    }

    return output.str();
}

void displayAllocationContext(const AllocationContext& allocation)
{
    std::cout << "\n[ALLOCATION] ";

    if (allocation.allocationBaseKnown)
        std::cout << "0x" << std::hex << std::uppercase << allocation.allocationBase << std::dec;
    else
        std::cout << "Base unavailable (region kept separate)";

    std::cout << " | " << memoryTypeToString(allocation.type)
              << " | Highest observed priority: " << priorityToString(allocation.priority) << '\n';
    std::cout << "  Observed committed regions: " << allocation.regionIndices.size()
              << " | Bytes: " << allocation.committedBytes
              << " | Executable: " << allocation.executableRegions
              << " | Ordinary W+X: " << allocation.writableExecutableRegions << '\n';

    switch (allocation.moduleStatus)
    {
        case ModuleAssociationStatus::Available:
            std::cout << "  Module association: " << contextTextToString(allocation.module.name) << '\n';
            std::cout << "  Module path: " << (allocation.module.path.empty()
                ? "Unavailable" : contextTextToString(allocation.module.path));

            if (allocation.module.pathMayBeTruncated)
                std::cout << " (may be truncated by Tool Help)";

            std::cout << '\n';
            break;

        case ModuleAssociationStatus::NotObserved:
            std::cout << "  Module association: No matching module observed in the snapshot\n";
            break;

        case ModuleAssociationStatus::Unavailable:
            std::cout << "  Module association: Unavailable";

            if (allocation.moduleErrorCode != ERROR_SUCCESS)
                std::cout << " (Windows error: " << allocation.moduleErrorCode << ')';

            std::cout << '\n';
            break;

        case ModuleAssociationStatus::NotQueried:
            std::cout << "  Module association: Not queried\n";
            break;

        case ModuleAssociationStatus::NotApplicable:
            std::cout << "  Module association: Not applicable to this reported memory type\n";
            break;
    }

    if (allocation.mappedFileStatus == MappedFileStatus::Available)
        std::cout << "  Mapped file (device path): " << contextTextToString(allocation.mappedFilePath) << '\n';
    else if (allocation.mappedFileStatus == MappedFileStatus::Unavailable)
    {
        std::cout << "  Mapped file: Unavailable (no filename obtained";

        if (allocation.mappedFileErrorCode != ERROR_SUCCESS)
            std::cout << "; Windows error: " << allocation.mappedFileErrorCode;

        std::cout << ")\n";
    }
    else if (allocation.mappedFileStatus == MappedFileStatus::NotQueried)
        std::cout << "  Mapped file: Not queried\n";
    else
        std::cout << "  Mapped file: Not applicable to this reported memory type\n";

    if (allocation.type == MEM_PRIVATE && allocation.executableRegions != 0)
        std::cout << "  Investigation context: Private executable allocation; origin is not established.\n";
}

void displayMemoryContextSummary(const MemoryContext& context)
{
    std::cout << "\n---------------- ALLOCATION CONTEXT ----------------\n";
    std::cout << "Observed allocation groups: " << context.allocations.size() << '\n';
    std::cout << "Module snapshot: ";

    switch (context.moduleSnapshot.status)
    {
        case ModuleSnapshotStatus::Complete: std::cout << "COMPLETE"; break;
        case ModuleSnapshotStatus::Partial: std::cout << "PARTIAL"; break;
        case ModuleSnapshotStatus::Failed: std::cout << "UNAVAILABLE"; break;
        case ModuleSnapshotStatus::NotQueried: std::cout << "NOT QUERIED"; break;
    }

    if (context.moduleSnapshot.errorCode != ERROR_SUCCESS)
        std::cout << " (Windows error: " << context.moduleSnapshot.errorCode << ')';

    std::cout << '\n';
    std::size_t moduleAssociations = 0;
    std::size_t unassociatedImages = 0;
    std::size_t unavailableAssociations = 0;
    std::size_t mappedFiles = 0;
    std::size_t missingMappedFiles = 0;

    for (const AllocationContext& allocation : context.allocations)
    {
        moduleAssociations += allocation.moduleStatus == ModuleAssociationStatus::Available;
        unassociatedImages += allocation.moduleStatus == ModuleAssociationStatus::NotObserved;
        unavailableAssociations += allocation.moduleStatus == ModuleAssociationStatus::Unavailable;
        mappedFiles += allocation.mappedFileStatus == MappedFileStatus::Available;
        missingMappedFiles += allocation.mappedFileStatus == MappedFileStatus::Unavailable;
    }

    std::cout << "Groups associated with observed modules: " << moduleAssociations << '\n';
    std::cout << "Image groups with no matching module observed: " << unassociatedImages << '\n';
    std::cout << "Image groups with unavailable module context: " << unavailableAssociations << '\n';
    std::cout << "Groups with mapped-file paths: " << mappedFiles << '\n';
    std::cout << "Groups with unavailable mapped-file paths: " << missingMappedFiles << '\n';
    std::cout << "[INFO] Context totals include all collected regions, independent of the display filter.\n";
    std::cout << "[INFO] Allocation totals cover observed committed regions, not reserved space.\n";
    std::cout << "[INFO] Module/file associations do not establish trustworthy contents or external access.\n";
    std::cout << "[INFO] Memory and module observations are not an atomic snapshot; unavailable context is not a finding.\n";
}
