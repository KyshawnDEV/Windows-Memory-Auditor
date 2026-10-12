
#include "MemoryScanner.h"

#include <iostream>
#include <iomanip>
#include <limits>
#include <cstdint>

/*
 * MemoryScanner.cpp
 *
 * Implements virtual memory enumeration and analysis.
 *
 * Windows API:
 *   GetNativeSystemInfo()
 *   VirtualQueryEx()
 *
 * Security Checks:
 *   - Writable and executable memory regions
 *
 * Note:
 *   Suspicious memory permissions are indicators,
 *   not confirmed security vulnerabilities.
 */


// ============================================================
// MEMORY PROTECTION CLASSIFICATION
// ============================================================

/*
 * Converts Windows memory protection constants
 * into readable permission strings.
 *
 * R = Read
 * W = Write
 * X = Execute
 * C = Copy-on-write
 *
 * Examples:
 *   PAGE_READWRITE         -> RW-
 *   PAGE_EXECUTE_READ      -> R-X
 *   PAGE_EXECUTE_READWRITE -> RWX
 */
std::string protectionToString(DWORD protection)
{
    /*
     * The lower byte contains the base protection.
     *
     * Additional flags such as PAGE_GUARD may also
     * be present in the original protection value.
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

    // Mark guarded memory regions.
    if (protection & PAGE_GUARD)
        result += "+GUARD";

    // Mark non-cacheable memory.
    if (protection & PAGE_NOCACHE)
        result += "+NC";

    return result;
}


// ============================================================
// MEMORY TYPE CLASSIFICATION
// ============================================================

/*
 * Converts the memory type into a readable string.
 *
 * MEM_IMAGE:
 *   Memory associated with executable images or DLLs.
 *
 * MEM_MAPPED:
 *   Memory backed by a mapped section.
 *
 * MEM_PRIVATE:
 *   Private memory belonging to the process.
 */
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
// WRITABLE / EXECUTABLE MEMORY DETECTION
// ============================================================

/*
 * Determines whether a region has both write and
 * execute permissions.
 *
 * PAGE_EXECUTE_READWRITE:
 *   Pages can be read, written, and executed.
 *
 * PAGE_EXECUTE_WRITECOPY:
 *   Pages can be executed and support copy-on-write.
 *
 * Guarded pages are excluded from this basic check
 * because access triggers guard-page handling.
 *
 * Returns:
 *   true  - Potentially interesting W+X configuration.
 *   false - No matching configuration.
 */
bool isWritableExecutable(DWORD protection)
{
    if (protection & PAGE_GUARD)
        return false;

    DWORD baseProtection = protection & 0xFF;

    return ( baseProtection == PAGE_EXECUTE_READWRITE || baseProtection == PAGE_EXECUTE_WRITECOPY);
}


// ============================================================
// MEMORY REGION ENUMERATION
// ============================================================

/*
 * enumerateMemoryRegions()
 *
 * Walks through the virtual address space of a process.
 *
 * Parameters:
 *   process - Handle returned by OpenProcess().
 *
 * Returns:
 *   A vector containing committed memory regions.
 *
 * The scanner does not read or modify memory contents.
 */
std::vector<MemoryRegion> enumerateMemoryRegions(HANDLE process)
{
    std::vector<MemoryRegion> regions;

    // --------------------------------------------------------
    // STEP 1: OBTAIN SYSTEM ADDRESS LIMITS
    // --------------------------------------------------------

    /*
     * SYSTEM_INFO contains information about the
     * current Windows system.
     *
     * Use the minimum and maximum application
     * addresses to bound our memory enumeration.
     */
    SYSTEM_INFO systemInfo{};

    GetNativeSystemInfo(&systemInfo);

    uintptr_t address =
        reinterpret_cast<uintptr_t>(
            systemInfo.lpMinimumApplicationAddress
        );

    uintptr_t maximumAddress =
        reinterpret_cast<uintptr_t>(
            systemInfo.lpMaximumApplicationAddress
        );

    // --------------------------------------------------------
    // STEP 2: WALK THE VIRTUAL ADDRESS SPACE
    // --------------------------------------------------------

    /*
     * VirtualQueryEx() describes the region containing
     * the supplied virtual address.
     *
     * After inspecting each region, advance to
     * the address immediately following that region.
     */
    while (address <= maximumAddress)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        SIZE_T result = VirtualQueryEx(
            process,
            reinterpret_cast<LPCVOID>(address),
            &mbi,
            sizeof(mbi)
        );

        /*
         * A return value of zero indicates failure.
         *
         * Report the address and error code.
         */
        if (result == 0)
        {
            std::cerr
                << "[ERROR] VirtualQueryEx failed at 0x"
                << std::hex << address << std::dec
                << ". Windows error: "
                << GetLastError() << '\n';

            break;
        }

        uintptr_t baseAddress =
            reinterpret_cast<uintptr_t>(mbi.BaseAddress);

        /*
         * Validate the region boundary before adding
         * the size to its base address.
         *
         * This prevents arithmetic overflow or
         * an infinite loop.
         */
        if (mbi.RegionSize == 0 ||
            mbi.RegionSize >
                std::numeric_limits<uintptr_t>::max()
                - baseAddress)
        {
            std::cerr
                << "[ERROR] Invalid memory region boundary.\n";

            break;
        }

        uintptr_t nextAddress =
            baseAddress + mbi.RegionSize;

        if (nextAddress <= address)
        {
            std::cerr
                << "[ERROR] Memory enumeration did not advance.\n";

            break;
        }

        // ----------------------------------------------------
        // STEP 3: COLLECT COMMITTED REGIONS
        // ----------------------------------------------------

        /*
         * MEM_COMMIT indicates that storage has been
         * committed for the region.
         *
         * Reserved and free regions are skipped in v0.3 currently
         */
        if (mbi.State == MEM_COMMIT)
        {
            MemoryRegion region{};

            region.baseAddress = baseAddress;
            region.regionSize = mbi.RegionSize;
            region.state = mbi.State;
            region.protection = mbi.Protect;
            region.allocationProtection = mbi.AllocationProtect;
            region.type = mbi.Type;

            regions.push_back(region);
        }

        // Continue to the next region.
        address = nextAddress;
    }

    return regions;
}


// ============================================================
// MEMORY REGION ANALYSIS
// ============================================================

/*
 * analyzeMemoryRegions()
 *
 * Displays collected memory regions and identifies
 * regions with writable/executable permissions.
 *
 * Parameters:
 *   regions - Memory regions collected by the scanner.
 *   metrics - Audit counters updated by this function.
 */
void analyzeMemoryRegions(const std::vector<MemoryRegion>& regions, AuditMetrics& metrics)
{
    std::cout << "\n================ MEMORY REGIONS ================\n\n";

    std::cout << std::left
          << std::setw(20) << "BASE ADDRESS"
          << std::setw(14) << "SIZE"
          << std::setw(12) << "TYPE"
          << std::setw(16) << "PROTECTION"
          << "FINDING\n";

    std::cout << std::string(85, '-') << '\n';

    for (const MemoryRegion& region : regions)
    {
        /*
         * A W+X region is worth investigating.
         *
         * It is not automatically a vulnerability.
         */
        bool suspicious = isWritableExecutable(region.protection);

        std::cout << "0x"
          << std::hex
          << std::uppercase
          << std::right
          << std::setfill('0')
          << std::setw(sizeof(uintptr_t) * 2)
          << region.baseAddress

          // Restore normal decimal formatting.
          << std::dec
          << std::setfill(' ')
          << std::left

          // Display region information.
          << "  "
          << std::setw(14) << region.regionSize
          << std::setw(12) << memoryTypeToString(region.type)
          << std::setw(16) << protectionToString(region.protection);

        if (suspicious)
        {
            std::cout << "[REVIEW] W+X";

            /*
             * For now, classify W+X regions as medium
             * severity indicators requiring review.
             *
             * Future analysis will use additional
             * evidence to determine severity.
             */
            metrics.medium++;
        }

        std::cout << '\n';
    }

    // --------------------------------------------------------
    // DISPLAY AUDIT SUMMARY
    // --------------------------------------------------------

    std::cout << "\n================ AUDIT SUMMARY ================\n";

    std::cout << "Committed regions: "
              << regions.size() << '\n';

    std::cout << "Critical findings: "
              << metrics.critical << '\n';

    std::cout << "High findings: "
              << metrics.high << '\n';

    std::cout << "Medium findings: "
              << metrics.medium << '\n';

    std::cout << "Low findings: "
              << metrics.low << '\n';
}
