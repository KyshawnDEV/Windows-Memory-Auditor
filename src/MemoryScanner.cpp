
#include "MemoryScanner.h"

#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
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
 * Version 0.4:
 *   - Reports complete, partial, and failed scans
 *   - Calculates committed memory statistics
 *   - Filters the displayed memory regions
 *   - Produces expanded audit summaries
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
 * Guarded pages are excluded from the current
 * accessible-executable classification.
 */
bool isExecutable(DWORD protection)
{
    if (protection & PAGE_GUARD)
        return false;

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
 * Checks for writable or copy-on-write permissions.
 *
 * Copy-on-write is included in this broad accounting
 * category, but differs from ordinary shared writes.
 */
bool isWritable(DWORD protection)
{
    if (protection & PAGE_GUARD)
        return false;

    DWORD baseProtection = protection & 0xFF;

    return (
        baseProtection == PAGE_READWRITE ||
        baseProtection == PAGE_WRITECOPY ||
        baseProtection == PAGE_EXECUTE_READWRITE ||
        baseProtection == PAGE_EXECUTE_WRITECOPY
    );
}


/*
 * isWritableExecutable()
 *
 * Detects memory with executable and writable or
 * copy-on-write permissions.
 *
 * A matching region is an indicator for review,
 * not proof of an exploitable vulnerability.
 */
bool isWritableExecutable(DWORD protection)
{
    return isExecutable(protection) && isWritable(protection);
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

    const std::uintptr_t maximumAddress = reinterpret_cast<std::uintptr_t > (systemInfo.lpMaximumApplicationAddress);

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

    statistics.totalRegions = regions.size();

    /*
     * Each region represents committed virtual memory.
     *
     * RegionSize measures the size of the address range,
     * not necessarily the physical RAM currently used.
     */
    for (const MemoryRegion& region : regions)
    {
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
        if (isExecutable(region.protection))
            statistics.executableBytes += size;

        if (isWritable(region.protection))
            statistics.writableBytes += size;

        // Count regions requiring W+X review.
        if (isWritableExecutable(region.protection))
            statistics.suspiciousRegions++;
    }

    return statistics;
}


// ============================================================
// MEMORY REGION DISPLAY
// ============================================================

void displayMemoryRegions(const std::vector<MemoryRegion>& regions, DisplayFilter filter)
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

        case DisplayFilter::Suspicious:
            std::cout << "Filter: W+X regions requiring review\n\n";
            break;
    }

    std::cout << std::left
              << std::setw(20) << "BASE ADDRESS"
              << std::setw(14) << "SIZE"
              << std::setw(12) << "TYPE"
              << std::setw(16) << "PROTECTION"
              << "FINDING\n";

    std::cout << std::string(85, '-') << '\n';

    std::size_t displayedRegions = 0;

    for (const MemoryRegion& region : regions)
    {
        bool executable = isExecutable(region.protection);

        bool suspicious = isWritableExecutable(region.protection);

        // ----------------------------------------------------
        // APPLY DISPLAY FILTER
        // ----------------------------------------------------

        if (filter == DisplayFilter::Executable && !executable) {
            continue;
        }

        if (filter == DisplayFilter::Suspicious && !suspicious) {
            continue;
        }

        displayedRegions++;

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
            << std::setw(16)
            << protectionToString(region.protection);

        if (suspicious)
            std::cout << "[REVIEW] W+X";

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

    if (result.status != ScanStatus::Complete)
    {
        std::cout << "Windows error: " << result.errorCode << '\n';

        std::cout << "Failure address: 0x"
                  << std::hex << std::uppercase
                  << result.failureAddress
                  << std::dec << '\n';

        std::cout << "[WARNING] Memory statistics may be incomplete.\n";
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

    std::cout << "Writable memory: " << statistics.writableBytes / MIB << " MiB\n";

    std::cout << "Private memory: " << statistics.privateBytes / MIB << " MiB\n";

    std::cout << "Image memory: " << statistics.imageBytes / MIB << " MiB\n";

    std::cout << "Mapped memory: " << statistics.mappedBytes / MIB << " MiB\n";

    // Restore default floating-point formatting.
    std::cout << std::defaultfloat;

    // --------------------------------------------------------
    // SECURITY FINDINGS
    // --------------------------------------------------------

    std::cout
        << "\n---------------- SECURITY FINDINGS ----------------\n";

    std::cout << "W+X regions: " << statistics.suspiciousRegions << '\n';

    std::cout << "Critical findings: " << metrics.critical << '\n';

    std::cout << "High findings: " << metrics.high << '\n';

    std::cout << "Medium findings: " << metrics.medium << '\n';

    std::cout << "Low findings: " << metrics.low << '\n';

    std::cout
        << "\n[INFO] W+X findings require investigation; "
        << "they are not confirmed vulnerabilities.\n";
}
