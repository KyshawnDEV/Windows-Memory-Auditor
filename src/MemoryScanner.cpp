
#include "MemoryScanner.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <string>

/*
 * MemoryScanner.cpp
 *
 * Implements memory enumeration, permission analysis,
 * filtering, and reporting.
 *
 * Windows API:
 *   GetNativeSystemInfo()
 *   VirtualQueryEx()
 *
 * Version 0.5:
 *   - Separates ordinary write from copy-on-write permissions
 *   - Classifies executable memory by its reported type
 *   - Preserves base permissions on guarded regions
 *   - Reports investigation priorities and analysis limitations
 *
 * Version 0.6:
 *   - Preserves the allocation base returned by Windows
 *   - Displays allocation context alongside filtered region rows
 *
 * The scanner does not read or modify memory contents.
 */

// ============================================================
// MEMORY PROTECTION CLASSIFICATION
// ============================================================

std::string protectionToString(DWORD protection)
{
    /*
     * The base protection occupies the low-order byte.
     *
     * Additional flags, such as PAGE_GUARD, can be
     * combined with the base protection.
     */
    DWORD baseProtection = protection & 0xFF;

    std::string result;

    switch (baseProtection)
    {
        case PAGE_NOACCESS:
            result = "---";
            break;

        case PAGE_READONLY:
            result = "R--";
            break;

        case PAGE_READWRITE:
            result = "RW-";
            break;

        case PAGE_WRITECOPY:
            result = "RC-";
            break;

        case PAGE_EXECUTE:
            result = "--X";
            break;

        case PAGE_EXECUTE_READ:
            result = "R-X";
            break;

        case PAGE_EXECUTE_READWRITE:
            result = "RWX";
            break;

        case PAGE_EXECUTE_WRITECOPY:
            result = "RCX";
            break;

        default:
            result = "???";
            break;
    }

    if (protection & PAGE_GUARD)
        result += "+GUARD";

    if (protection & PAGE_NOCACHE)
        result += "+NC";

    if (protection & PAGE_WRITECOMBINE)
        result += "+WC";

    return result;
}


// ============================================================
// MEMORY TYPE CLASSIFICATION
// ============================================================

std::string memoryTypeToString(DWORD type)
{
    switch (type)
    {
        case MEM_IMAGE:
            return "IMAGE";

        case MEM_MAPPED:
            return "MAPPED";

        case MEM_PRIVATE:
            return "PRIVATE";

        default:
            return "UNKNOWN";
    }
}


// ============================================================
// MEMORY PERMISSION CHECKS
// ============================================================

/*
 * isExecutable()
 *
 * Determines whether the region has an executable
 * base protection.
 *
 * PAGE_GUARD is a one-time access alarm, not a replacement
 * for the underlying permissions. Classification retains
 * execute permission without claiming immediate access.
 */
bool isExecutable(DWORD protection)
{
    DWORD baseProtection = protection & 0xFF;

    return (
        baseProtection == PAGE_EXECUTE ||
        baseProtection == PAGE_EXECUTE_READ ||
        baseProtection == PAGE_EXECUTE_READWRITE ||
        baseProtection == PAGE_EXECUTE_WRITECOPY
    );
}


/*
 * isWritable()
 *
 * Checks for ordinary write permissions only.
 *
 * Ordinary write can apply to private or mapped memory.
 * It does not imply that another process can write here.
 * Copy-on-write is accounted for separately below.
 */
bool isWritable(DWORD protection)
{
    DWORD baseProtection = protection & 0xFF;

    return (
        baseProtection == PAGE_READWRITE ||
        baseProtection == PAGE_EXECUTE_READWRITE
    );
}


/*
 * isWritableExecutable()
 *
 * Detects memory with ordinary write and execute permissions.
 *
 * A matching region is an indicator for review,
 * not proof of an exploitable vulnerability.
 */
bool isWritableExecutable(DWORD protection)
{
    return isExecutable(protection) && isWritable(protection);
}


/*
 * isCopyOnWrite()
 *
 * A write to a copy-on-write mapping creates a private
 * copy for the writing process. It does not modify the
 * original shared backing through that mapping.
 *
 * VirtualQueryEx() can still report MEM_IMAGE or MEM_MAPPED
 * after a page becomes private. This scanner reports region
 * metadata and does not determine page-level sharing.
 */
bool isCopyOnWrite(DWORD protection)
{
    DWORD baseProtection = protection & 0xFF;

    return baseProtection == PAGE_WRITECOPY ||
           baseProtection == PAGE_EXECUTE_WRITECOPY;
}


// ============================================================
// MEMORY EXPOSURE CLASSIFICATION
// ============================================================

MemoryExposure classifyMemoryExposure(const MemoryRegion& region)
{
    MemoryExposure exposure{};

    // Protection values on reserved or free memory are not findings.
    if (region.state != MEM_COMMIT)
        return exposure;

    exposure.guarded = (region.protection & PAGE_GUARD) != 0;

    /*
     * An unrecognized base protection must not be described
     * as known non-executable memory. Preserve the raw value
     * in the region table and leave its permissions unknown.
     */
    switch (region.protection & 0xFF)
    {
        case PAGE_NOACCESS:
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            break;

        default:
            exposure.category = ExposureCategory::UnknownProtection;
            exposure.priority = InvestigationPriority::Low;
            return exposure;
    }

    exposure.executable = isExecutable(region.protection);
    exposure.writable = isWritable(region.protection);
    exposure.copyOnWrite = isCopyOnWrite(region.protection);

    if (!exposure.executable)
    {
        if (exposure.copyOnWrite)
            exposure.category = ExposureCategory::CopyOnWrite;
        else if (exposure.writable)
            exposure.category = ExposureCategory::Writable;

        return exposure;
    }

    /*
     * Executable COW receives its own category regardless
     * of reported type. It must not inflate ordinary W+X
     * totals or be treated as a shared writable code mapping.
     */
    if (exposure.copyOnWrite)
    {
        exposure.category = ExposureCategory::ExecutableCopyOnWrite;
        exposure.priority = InvestigationPriority::Low;
        return exposure;
    }

    switch (region.type)
    {
        case MEM_PRIVATE:
            exposure.category = exposure.writable
                ? ExposureCategory::PrivateWritableExecutable
                : ExposureCategory::PrivateExecutable;
            exposure.priority = exposure.writable
                ? InvestigationPriority::High
                : InvestigationPriority::Medium;
            break;

        case MEM_IMAGE:
            exposure.category = exposure.writable
                ? ExposureCategory::ImageWritableExecutable
                : ExposureCategory::ImageExecutable;
            exposure.priority = exposure.writable
                ? InvestigationPriority::Medium
                : InvestigationPriority::None;
            break;

        case MEM_MAPPED:
            exposure.category = exposure.writable
                ? ExposureCategory::MappedWritableExecutable
                : ExposureCategory::MappedExecutable;
            exposure.priority = exposure.writable
                ? InvestigationPriority::Medium
                : InvestigationPriority::None;
            break;

        default:
            exposure.category = exposure.writable
                ? ExposureCategory::OtherWritableExecutable
                : ExposureCategory::OtherExecutable;
            exposure.priority = exposure.writable
                ? InvestigationPriority::Medium
                : InvestigationPriority::Low;
            break;
    }

    return exposure;
}


std::string exposureToString(ExposureCategory category)
{
    switch (category)
    {
        case ExposureCategory::None: return "No current write/execute permissions observed";
        case ExposureCategory::UnknownProtection: return "Unknown base protection";
        case ExposureCategory::Writable: return "Writable (non-executable)";
        case ExposureCategory::CopyOnWrite: return "Copy-on-write (non-executable)";
        case ExposureCategory::PrivateExecutable: return "Private executable";
        case ExposureCategory::PrivateWritableExecutable: return "Private W+X";
        case ExposureCategory::ImageExecutable: return "Image executable";
        case ExposureCategory::ImageWritableExecutable: return "Image W+X";
        case ExposureCategory::MappedExecutable: return "Mapped executable";
        case ExposureCategory::MappedWritableExecutable: return "Mapped W+X";
        case ExposureCategory::ExecutableCopyOnWrite: return "Executable copy-on-write";
        case ExposureCategory::OtherExecutable: return "Executable (unknown type)";
        case ExposureCategory::OtherWritableExecutable: return "W+X (unknown type)";
    }

    return "Unknown classification";
}


std::string priorityToString(InvestigationPriority priority)
{
    switch (priority)
    {
        case InvestigationPriority::None: return "INFO";
        case InvestigationPriority::Low: return "LOW";
        case InvestigationPriority::Medium: return "MEDIUM";
        case InvestigationPriority::High: return "HIGH";
    }

    return "UNKNOWN";
}


bool matchesDisplayFilter(const MemoryExposure& exposure, DisplayFilter filter)
{
    switch (filter)
    {
        case DisplayFilter::All: return true;
        case DisplayFilter::Executable: return exposure.executable;
        case DisplayFilter::WritableExecutable:
            return exposure.executable && exposure.writable;
        case DisplayFilter::Review:
            return exposure.priority != InvestigationPriority::None;
    }

    return false;
}


AuditMetrics calculateAuditMetrics(const std::vector<MemoryRegion>& regions)
{
    AuditMetrics metrics{};

    // One region contributes once, even when it has multiple attributes.
    for (const MemoryRegion& region : regions)
    {
        switch (classifyMemoryExposure(region).priority)
        {
            case InvestigationPriority::High: metrics.high++; break;
            case InvestigationPriority::Medium: metrics.medium++; break;
            case InvestigationPriority::Low: metrics.low++; break;
            case InvestigationPriority::None: break;
        }
    }

    return metrics;
}


// ============================================================
// MEMORY REGION ENUMERATION
// ============================================================

ScanResult enumerateMemoryRegions(HANDLE process)
{
    ScanResult scanResult{};

    // --------------------------------------------------------
    // STEP 1: VALIDATE PROCESS HANDLE
    // --------------------------------------------------------

    if (process == nullptr ||
        process == INVALID_HANDLE_VALUE)
    {
        scanResult.errorCode = ERROR_INVALID_HANDLE;
        return scanResult;
    }

    // --------------------------------------------------------
    // STEP 2: OBTAIN SYSTEM ADDRESS LIMITS
    // --------------------------------------------------------

    SYSTEM_INFO systemInfo{};
    GetNativeSystemInfo(&systemInfo);

    std::uintptr_t address =
        reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);

    std::uintptr_t maximumAddress =
        reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);

    /*
     * A native x64 scanner can query WOW64 processes, but
     * their pointers cannot address memory above 4 GiB.
     * Do not walk the remaining native x64 address space.
     *
     * Some targets may have a smaller accessible range.
     * A query failure below this upper bound remains partial;
     * ERROR_INVALID_PARAMETER alone is not proof of completion.
     */
    BOOL targetWow64 = FALSE;

    if (!IsWow64Process(process, &targetWow64))
    {
        scanResult.errorCode = GetLastError();
        return scanResult;
    }

    scanResult.targetWow64 = targetWow64 != FALSE;

    if (scanResult.targetWow64)
    {
        const std::uintptr_t wow64Maximum =
            static_cast<std::uintptr_t>(std::numeric_limits<std::uint32_t>::max());

        if (maximumAddress > wow64Maximum)
            maximumAddress = wow64Maximum;
    }

    scanResult.maximumAddress = maximumAddress;
    scanResult.minimumAddress = address;

    // --------------------------------------------------------
    // STEP 3: WALK THE VIRTUAL ADDRESS SPACE
    // --------------------------------------------------------

    while (address <= maximumAddress)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        SIZE_T bytesReturned = VirtualQueryEx(
            process,
            reinterpret_cast<LPCVOID>(address),
            &mbi,
            sizeof(mbi)
        );

        /*
         * VirtualQueryEx() returns zero on failure.
         *
         * Preserve both the error code and the address
         * so the user can identify where scanning stopped.
         */
        if (bytesReturned == 0)
        {
            scanResult.errorCode = GetLastError();
            scanResult.failureAddress = address;

            scanResult.status =
                scanResult.queriedRegions == 0
                ? ScanStatus::Failed
                : ScanStatus::Partial;

            return scanResult;
        }

        scanResult.queriedRegions++;

        // Do not interpret a partially populated query structure.
        if (bytesReturned != sizeof(mbi))
        {
            scanResult.errorCode = ERROR_INVALID_DATA;
            scanResult.failureAddress = address;
            scanResult.status = ScanStatus::Partial;
            return scanResult;
        }

        std::uintptr_t baseAddress =
            reinterpret_cast<std::uintptr_t>(
                mbi.BaseAddress
            );

        // ----------------------------------------------------
        // STEP 4: VALIDATE REGION BOUNDARIES
        // ----------------------------------------------------

        /*
         * Ensure that adding RegionSize to BaseAddress
         * cannot overflow uintptr_t.
         */
        if (mbi.RegionSize == 0 ||
            mbi.RegionSize >
                std::numeric_limits<std::uintptr_t>::max()
                - baseAddress)
        {
            scanResult.errorCode = ERROR_INVALID_DATA;
            scanResult.failureAddress = address;

            scanResult.status = ScanStatus::Partial;
            return scanResult;
        }

        std::uintptr_t nextAddress =
            baseAddress + mbi.RegionSize;

        /*
         * A valid query must advance the address.
         *
         * Otherwise the loop could run indefinitely.
         */
        if (nextAddress <= address)
        {
            scanResult.errorCode = ERROR_INVALID_DATA;
            scanResult.failureAddress = address;

            scanResult.status = ScanStatus::Partial;
            return scanResult;
        }

        // ----------------------------------------------------
        // STEP 5: COLLECT COMMITTED REGIONS
        // ----------------------------------------------------

        if (mbi.State == MEM_COMMIT)
        {
            MemoryRegion region{};

            region.baseAddress = baseAddress;
            region.allocationBase = reinterpret_cast<std::uintptr_t>(mbi.AllocationBase);
            region.regionSize = mbi.RegionSize;
            region.state = mbi.State;
            region.protection = mbi.Protect;
            region.allocationProtection = mbi.AllocationProtect;
            region.type = mbi.Type;

            scanResult.regions.push_back(region);
        }

        // Move to the next virtual memory region.
        address = nextAddress;
    }

    // --------------------------------------------------------
    // STEP 6: MARK SUCCESSFUL COMPLETION
    // --------------------------------------------------------

    scanResult.status = ScanStatus::Complete;
    scanResult.errorCode = ERROR_SUCCESS;

    return scanResult;
}


// ============================================================
// MEMORY STATISTICS
// ============================================================

MemoryStatistics calculateMemoryStatistics(const std::vector<MemoryRegion>& regions)
{
    MemoryStatistics statistics{};

    /*
     * Each region represents committed virtual memory.
     *
     * RegionSize measures the size of the address range,
     * not necessarily the physical RAM currently used.
     */
    for (const MemoryRegion& region : regions)
    {
        // Public callers may supply regions not collected by the scanner.
        if (region.state != MEM_COMMIT)
            continue;

        statistics.totalRegions++;
        MemoryExposure exposure = classifyMemoryExposure(region);
        std::uint64_t size = static_cast<std::uint64_t>(region.regionSize);

        // Total committed virtual memory.
        statistics.committedBytes += size;

        // Memory type totals.
        switch (region.type)
        {
            case MEM_PRIVATE:
                statistics.privateBytes += size;
                break;

            case MEM_IMAGE:
                statistics.imageBytes += size;
                break;

            case MEM_MAPPED:
                statistics.mappedBytes += size;
                break;
        }

        // Permission-based totals.
        if (exposure.executable)
            statistics.executableBytes += size;

        if (exposure.writable)
            statistics.writableBytes += size;

        if (exposure.copyOnWrite)
            statistics.copyOnWriteBytes += size;

        if (exposure.guarded)
            statistics.guardedBytes += size;

        if (exposure.executable && exposure.copyOnWrite)
        {
            statistics.executableCopyOnWriteBytes += size;
            statistics.executableCopyOnWriteRegions++;
        }

        if (exposure.executable && exposure.writable)
        {
            statistics.writableExecutableBytes += size;
            statistics.writableExecutableRegions++;
        }

        if (exposure.executable && region.type == MEM_PRIVATE)
        {
            statistics.privateExecutableBytes += size;
            statistics.privateExecutableRegions++;

            if (exposure.writable)
            {
                statistics.privateWritableExecutableBytes += size;
                statistics.privateWritableExecutableRegions++;
            }
        }
        else if (exposure.executable && region.type == MEM_IMAGE)
            statistics.imageExecutableBytes += size;
        else if (exposure.executable && region.type == MEM_MAPPED)
            statistics.mappedExecutableBytes += size;
    }

    return statistics;
}


// ============================================================
// MEMORY REGION DISPLAY
// ============================================================

void displayMemoryRegions(const std::vector<MemoryRegion>& regions, DisplayFilter filter,
    const MemoryContext* context)
{
    std::cout << "\n================ MEMORY REGIONS ================\n\n";

    switch (filter)
    {
        case DisplayFilter::All:
            std::cout << "Filter: All committed regions\n\n";
            break;

        case DisplayFilter::Executable:
            std::cout << "Filter: Executable regions\n\n";
            break;

        case DisplayFilter::WritableExecutable:
            std::cout << "Filter: Ordinary W+X regions (excludes copy-on-write)\n\n";
            break;

        case DisplayFilter::Review:
            std::cout << "Filter: Regions with an investigation priority\n\n";
            break;
    }

    std::cout << std::left
              << std::setw(20) << "BASE ADDRESS"
              << std::setw(14) << "SIZE"
              << std::setw(12) << "TYPE"
              << std::setw(20) << "PROTECTION"
              << "PRIORITY / EXPOSURE\n";

    std::cout << std::string(85, '-') << '\n';

    std::size_t displayedRegions = 0;

    /*
     * Index allocation context by the original region position.
     * Context collection must not reorder regions or alter filtering.
     * Print each allocation header only when a matching row is shown.
     */
    std::vector<const AllocationContext*> regionContexts(regions.size(), nullptr);
    std::set<const AllocationContext*> displayedAllocations;

    if (context != nullptr)
    {
        for (const AllocationContext& allocation : context->allocations)
        {
            for (std::size_t index : allocation.regionIndices)
            {
                if (index < regionContexts.size())
                    regionContexts[index] = &allocation;
            }
        }
    }

    for (std::size_t index = 0; index < regions.size(); index++)
    {
        const MemoryRegion& region = regions[index];
        MemoryExposure exposure = classifyMemoryExposure(region);

        // ----------------------------------------------------
        // APPLY DISPLAY FILTER
        // ----------------------------------------------------

        if (!matchesDisplayFilter(exposure, filter)) {
            continue;
        }

        displayedRegions++;

        const AllocationContext* allocation = regionContexts[index];

        if (allocation != nullptr && displayedAllocations.insert(allocation).second)
            displayAllocationContext(*allocation);

        // ----------------------------------------------------
        // PRINT REGION INFORMATION
        // ----------------------------------------------------

        /*
         * std::right and zero padding ensure that
         * hexadecimal addresses have leading zeros.
         *
         * Restore decimal formatting and left alignment
         * before printing the remaining columns.
         */
        std::cout
            << "0x"
            << std::hex
            << std::uppercase
            << std::right
            << std::setfill('0')
            << std::setw(sizeof(std::uintptr_t) * 2)
            << region.baseAddress
            << std::dec
            << std::setfill(' ')
            << std::left
            << "  "
            << std::setw(14) << region.regionSize
            << std::setw(12)
            << memoryTypeToString(region.type)
            << std::setw(20)
            << protectionToString(region.protection);

        std::cout << '[' << priorityToString(exposure.priority) << "] "
                  << exposureToString(exposure.category);

        if (exposure.guarded)
            std::cout << " (guarded; base permissions shown)";

        std::cout << '\n';
    }

    std::cout << "\nDisplayed regions: "
              << displayedRegions
              << " / " << regions.size() << '\n';
}


// ============================================================
// AUDIT SUMMARY
// ============================================================

void displayAuditSummary(const ScanResult& result, const MemoryStatistics& statistics, const AuditMetrics& metrics)
{
    constexpr double MIB = 1024.0 * 1024.0;

    std::cout << "\n================ AUDIT SUMMARY ================\n";

    // --------------------------------------------------------
    // SCAN STATUS
    // --------------------------------------------------------

    std::cout << "Scan status: ";

    switch (result.status)
    {
        case ScanStatus::Complete:
            std::cout << "COMPLETE\n";
            break;

        case ScanStatus::Partial:
            std::cout << "PARTIAL\n";
            break;

        case ScanStatus::Failed:
            std::cout << "FAILED\n";
            break;
    }

    std::cout << "Regions queried: " << result.queriedRegions << '\n';

    if (result.maximumAddress != 0)
    {
        std::cout << "Target architecture: "
                  << (result.targetWow64 ? "WOW64 (32-bit)" : "Native 64-bit") << '\n';
        std::cout << "Scan upper bound: 0x" << std::hex << std::uppercase
                  << result.maximumAddress << std::dec << '\n';
    }

    if (result.status != ScanStatus::Complete)
    {
        std::cout << "Windows error: " << result.errorCode << '\n';

        std::cout << "Failure address: 0x"
                  << std::hex << std::uppercase
                  << result.failureAddress
                  << std::dec << '\n';

        std::cout << "[WARNING] Memory statistics may be incomplete.\n";

        if (result.targetWow64 && result.errorCode == ERROR_INVALID_PARAMETER)
        {
            std::cout << "[INFO] The target may have a smaller accessible address range.\n";
            std::cout << "[INFO] Completion could not be established; the scan remains PARTIAL.\n";
        }
    }

    // --------------------------------------------------------
    // MEMORY STATISTICS
    // --------------------------------------------------------

    std::cout << "\n---------------- MEMORY STATISTICS ----------------\n";

    std::cout << "Committed regions: " << statistics.totalRegions << '\n';

    /*
     * Convert byte totals into MiB.
     *
     * 1 MiB = 1,048,576 bytes.
     */
    std::cout << std::fixed << std::setprecision(2);

    std::cout << "Committed memory: " << statistics.committedBytes / MIB << " MiB\n";

    std::cout << "Executable memory: " << statistics.executableBytes / MIB << " MiB\n";

    std::cout << "Ordinary writable memory: " << statistics.writableBytes / MIB << " MiB\n";
    std::cout << "Copy-on-write memory: " << statistics.copyOnWriteBytes / MIB << " MiB\n";
    std::cout << "Ordinary W+X memory: " << statistics.writableExecutableBytes / MIB << " MiB\n";
    std::cout << "Executable copy-on-write: " << statistics.executableCopyOnWriteBytes / MIB << " MiB\n";
    std::cout << "Private executable memory: " << statistics.privateExecutableBytes / MIB << " MiB\n";
    std::cout << "Private W+X memory (subset): " << statistics.privateWritableExecutableBytes / MIB << " MiB\n";
    std::cout << "Image executable memory: " << statistics.imageExecutableBytes / MIB << " MiB\n";
    std::cout << "Mapped executable memory: " << statistics.mappedExecutableBytes / MIB << " MiB\n";
    std::cout << "Guarded memory (overlaps permission totals): " << statistics.guardedBytes / MIB << " MiB\n";

    std::cout << "Private memory: " << statistics.privateBytes / MIB << " MiB\n";

    std::cout << "Image memory: " << statistics.imageBytes / MIB << " MiB\n";

    std::cout << "Mapped memory: " << statistics.mappedBytes / MIB << " MiB\n";

    // Restore default floating-point formatting.
    std::cout << std::defaultfloat;

    // --------------------------------------------------------
    // SECURITY FINDINGS
    // --------------------------------------------------------

    std::cout
        << "\n---------------- INVESTIGATION PRIORITIES ----------------\n";

    std::cout << "Ordinary W+X regions: " << statistics.writableExecutableRegions << '\n';
    std::cout << "Executable copy-on-write regions: " << statistics.executableCopyOnWriteRegions << '\n';
    std::cout << "Private executable regions: " << statistics.privateExecutableRegions << '\n';
    std::cout << "Private W+X regions (subset): " << statistics.privateWritableExecutableRegions << '\n';
    std::cout << "High priority regions: " << metrics.high << '\n';
    std::cout << "Medium priority regions: " << metrics.medium << '\n';
    std::cout << "Low priority regions: " << metrics.low << '\n';

    std::cout
        << "\n[INFO] Priorities guide investigation; they do not establish "
        << "malware or confirmed vulnerabilities.\n"
        << "[INFO] High: private W+X. Medium: other W+X or private executable.\n"
        << "[INFO] Low: executable copy-on-write, executable memory of unknown type, or unknown protection.\n"
        << "[INFO] JIT runtimes and other legitimate applications can use private executable memory.\n"
        << "[INFO] External write access: NOT ASSESSED. Region permissions alone do not establish it.\n"
        << "[INFO] Guarded regions retain base permission classification; immediate access is not implied.\n"
        << "[INFO] MEM_PRIVATE is a reported region type; modified COW pages can remain IMAGE or MAPPED.\n"
        << "[INFO] Statistics describe observed committed virtual memory, not physical RAM or a frozen snapshot.\n";
}
