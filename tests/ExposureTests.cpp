#include "MemoryScanner.h"
#include "WindowsHandle.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * ExposureTests.cpp
 *
 * Verifies v0.5 classifications, totals, filters, and reporting.
 * Real Windows allocations also verify that metadata-only
 * enumeration observes private and copy-on-write configurations.
 *
 * Tests never execute code from their allocations. Guarded
 * memory is queried without touching its contents.
 *
 * Test Groups:
 *   - Base permissions and protection modifiers
 *   - Region categories, byte totals, and filter membership
 *   - Console reporting and incomplete scan warnings
 *   - Enumeration of real Windows memory allocations
 *
 * Synthetic regions provide predictable expected results.
 * Live fixtures check that those rules also match metadata
 * returned by Windows. A failure throws an exception that
 * main() converts into a nonzero exit code for CTest.
 */

// ============================================================
// TEST HELPERS
// ============================================================

/*
 * require()
 *
 * Parameters:
 *   condition - The behavior that must be true for the test to pass.
 *   message - Describes the failed check if condition is false.
 *
 * Unlike assert(), this helper is not disabled by NDEBUG.
 * The same checks therefore run in Debug and Release builds.
 */
void require(bool condition, const std::string& message)
{
    // Explicit failures remain active in both Debug and Release builds.
    if (!condition)
        throw std::runtime_error(message);
}

/*
 * makeRegion()
 *
 * Creates synthetic metadata without allocating or accessing memory.
 * The address is only a label used to distinguish displayed rows.
 * It must not be dereferenced as a real process address.
 *
 * All synthetic regions start as committed 4096-byte ranges.
 * This fixed size makes expected totals easy to calculate.
 * Live fixtures below obtain the actual Windows page size instead.
 */
MemoryRegion makeRegion(DWORD protection, DWORD type, std::uintptr_t address = 0x10000)
{
    MemoryRegion region{};
    region.baseAddress = address;
    region.regionSize = 4096;
    region.state = MEM_COMMIT;
    region.protection = protection;
    region.type = type;
    return region;
}


// ============================================================
// BASE PERMISSION CHECKS
// ============================================================

/*
 * testPermissions()
 *
 * Checks permission helpers independently of memory type.
 * Ordinary write and copy-on-write must remain separate,
 * and modifiers must not erase the base permissions.
 */
void testPermissions()
{
    // Each row states the expected meaning of one Windows base protection.
    struct ExpectedPermissions
    {
        DWORD protection;
        bool executable;
        bool writable;
        bool copyOnWrite;
    };

    /*
     * The Boolean columns are executable, ordinary writable,
     * and copy-on-write, in that order.
     *
     * PAGE_EXECUTE_WRITECOPY permits executable COW behavior,
     * but it must not count as ordinary writable memory.
     */
    const ExpectedPermissions cases[] =
    {
        {PAGE_NOACCESS, false, false, false},
        {PAGE_READONLY, false, false, false},
        {PAGE_READWRITE, false, true, false},
        {PAGE_WRITECOPY, false, false, true},
        {PAGE_EXECUTE, true, false, false},
        {PAGE_EXECUTE_READ, true, false, false},
        {PAGE_EXECUTE_READWRITE, true, true, false},
        {PAGE_EXECUTE_WRITECOPY, true, false, true}
    };

    /*
     * Zero tests the base protection by itself. Other entries
     * add one modifier using bitwise OR.
     *
     * These are synthetic masking checks: some combinations,
     * such as PAGE_NOACCESS | PAGE_GUARD, cannot be allocated
     * through Windows APIs. No such allocation is attempted.
     */
    const DWORD modifiers[] = {0, PAGE_GUARD, PAGE_NOCACHE, PAGE_WRITECOMBINE};

    for (const ExpectedPermissions& expected : cases)
    {
        for (DWORD modifier : modifiers)
        {
            DWORD protection = expected.protection | modifier;
            // Compare against the table, not another classification helper.
            require(isExecutable(protection) == expected.executable, "Execute permission mismatch");
            require(isWritable(protection) == expected.writable, "Ordinary write permission mismatch");
            require(isCopyOnWrite(protection) == expected.copyOnWrite, "COW permission mismatch");
            require(isWritableExecutable(protection) == (expected.executable && expected.writable),
                    "COW or guard incorrectly changed ordinary W+X detection");
        }
    }

    /*
     * Reserved address space is not committed memory.
     * Deliberately leave an RWX value in the synthetic record
     * to ensure the state check takes precedence over protection.
     */
    MemoryRegion reserved = makeRegion(PAGE_EXECUTE_READWRITE, MEM_PRIVATE);
    reserved.state = MEM_RESERVE;
    require(classifyMemoryExposure(reserved).priority == InvestigationPriority::None,
            "Reserved memory received a priority");
    require(calculateMemoryStatistics({reserved}).committedBytes == 0 &&
            calculateMemoryStatistics({reserved}).totalRegions == 0,
            "Reserved memory inflated committed totals");

    // Zero is not PAGE_NOACCESS; it is an unrecognized base protection here.
    MemoryExposure unknown = classifyMemoryExposure(makeRegion(0, MEM_PRIVATE));
    require(unknown.category == ExposureCategory::UnknownProtection && !unknown.executable,
            "Unknown protection was treated as known permissions");
    // Verify that the readable protection label retains the cache modifier.
    require(protectionToString(PAGE_READWRITE | PAGE_WRITECOMBINE) == "RW-+WC",
            "Write-combine modifier missing");
}


// ============================================================
// CATEGORIES, STATISTICS, AND FILTERS
// ============================================================

/*
 * testAnalysis()
 *
 * Uses one deterministic collection to compare classification,
 * filter membership, byte statistics, and investigation counts.
 * This catches disagreements between different reporting paths.
 */
void testAnalysis()
{
    /*
     * Eleven regions cover private, image, and mapped memory;
     * ordinary write, execute, COW, guard, and no-access cases.
     *
     * Distinct addresses make rows recognizable in a report.
     * Each region is 4096 bytes, regardless of its permissions.
     */
    const std::vector<MemoryRegion> regions =
    {
        makeRegion(PAGE_EXECUTE_READWRITE, MEM_PRIVATE, 0x10000),
        makeRegion(PAGE_EXECUTE_READ, MEM_PRIVATE, 0x20000),
        makeRegion(PAGE_READWRITE, MEM_PRIVATE, 0x30000),
        makeRegion(PAGE_EXECUTE_READ, MEM_IMAGE, 0x40000),
        makeRegion(PAGE_EXECUTE_READWRITE, MEM_IMAGE, 0x50000),
        makeRegion(PAGE_EXECUTE_READ, MEM_MAPPED, 0x60000),
        makeRegion(PAGE_EXECUTE_READWRITE, MEM_MAPPED, 0x70000),
        makeRegion(PAGE_EXECUTE_WRITECOPY, MEM_IMAGE, 0x80000),
        makeRegion(PAGE_WRITECOPY, MEM_MAPPED, 0x90000),
        makeRegion(PAGE_EXECUTE_READWRITE | PAGE_GUARD, MEM_PRIVATE, 0xA0000),
        makeRegion(PAGE_NOACCESS, MEM_PRIVATE, 0xB0000)
    };

    // Expected categories correspond to the region vector in the same order.
    const ExposureCategory categories[] =
    {
        ExposureCategory::PrivateWritableExecutable,
        ExposureCategory::PrivateExecutable,
        ExposureCategory::Writable,
        ExposureCategory::ImageExecutable,
        ExposureCategory::ImageWritableExecutable,
        ExposureCategory::MappedExecutable,
        ExposureCategory::MappedWritableExecutable,
        ExposureCategory::ExecutableCopyOnWrite,
        ExposureCategory::CopyOnWrite,
        ExposureCategory::PrivateWritableExecutable,
        ExposureCategory::None
    };

    // Count which rows each filter would display without printing a table.
    std::size_t executableRows = 0;
    std::size_t writableExecutableRows = 0;
    std::size_t reviewRows = 0;

    for (std::size_t index = 0; index < regions.size(); index++)
    {
        MemoryExposure exposure = classifyMemoryExposure(regions[index]);
        require(exposure.category == categories[index], "Exposure category mismatch");
        // Boolean results add one for a matching row and zero otherwise.
        executableRows += matchesDisplayFilter(exposure, DisplayFilter::Executable);
        writableExecutableRows += matchesDisplayFilter(exposure, DisplayFilter::WritableExecutable);
        reviewRows += matchesDisplayFilter(exposure, DisplayFilter::Review);
    }

    // Statistics and priority counts always use the complete input collection.
    MemoryStatistics statistics = calculateMemoryStatistics(regions);
    AuditMetrics metrics = calculateAuditMetrics(regions);
    constexpr std::uint64_t PAGE_BYTES = 4096;

    /*
     * Expected Totals:
     *   - 11 committed regions, including the no-access region
     *   - 8 executable regions, including executable COW and guard
     *   - 5 ordinary writable regions and 2 separate COW regions
     *   - 4 ordinary W+X regions and 1 executable COW region
     *
     * Multiply region counts by PAGE_BYTES to obtain byte totals.
     * Permission totals overlap: an ordinary W+X region is both
     * executable and writable, but is counted once as a W+X region.
     */
    require(statistics.totalRegions == 11 && statistics.committedBytes == 11 * PAGE_BYTES,
            "Committed totals mismatch");
    require(statistics.executableBytes == 8 * PAGE_BYTES && executableRows == 8,
            "Executable filter and totals disagree");
    require(statistics.writableBytes == 5 * PAGE_BYTES && statistics.copyOnWriteBytes == 2 * PAGE_BYTES,
            "Ordinary write and COW totals overlap");
    require(statistics.writableExecutableBytes == 4 * PAGE_BYTES &&
            statistics.writableExecutableRegions == 4 && writableExecutableRows == 4,
            "Ordinary W+X filter and totals disagree");
    require(statistics.executableCopyOnWriteBytes == PAGE_BYTES &&
            statistics.executableCopyOnWriteRegions == 1, "Executable COW total mismatch");
    // Three private executable regions include two ordinary W+X regions.
    require(statistics.privateExecutableBytes == 3 * PAGE_BYTES &&
            statistics.privateExecutableRegions == 3 &&
            statistics.privateWritableExecutableBytes == 2 * PAGE_BYTES &&
            statistics.privateWritableExecutableRegions == 2, "Private executable totals mismatch");
    // The executable COW image belongs to image executable totals as well.
    require(statistics.imageExecutableBytes == 3 * PAGE_BYTES &&
            statistics.mappedExecutableBytes == 2 * PAGE_BYTES, "Executable type totals mismatch");
    require(statistics.privateBytes == 5 * PAGE_BYTES && statistics.imageBytes == 3 * PAGE_BYTES &&
            statistics.mappedBytes == 3 * PAGE_BYTES, "Memory type totals mismatch");
    // Guarded bytes overlap the private, writable, executable, and W+X totals.
    require(statistics.guardedBytes == PAGE_BYTES, "Guarded bytes missing");
    /*
     * Two private W+X regions receive high priority.
     * Private RX, image W+X, and mapped W+X receive medium priority.
     * Executable COW receives low priority.
     *
     * These six regions must match the investigation filter.
     * Informational regions do not receive a priority count.
     */
    require(metrics.high == 2 && metrics.medium == 3 && metrics.low == 1 && reviewRows == 6,
            "Priority counts double-count or omit regions");

    // An unknown memory type must not hide known ordinary W+X permissions.
    MemoryExposure other = classifyMemoryExposure(makeRegion(PAGE_EXECUTE_READWRITE, 0));
    require(other.category == ExposureCategory::OtherWritableExecutable &&
            other.priority == InvestigationPriority::Medium, "Unknown executable type ignored");

    /*
     * Simulate an allocation originally created as RWX but now readonly.
     * AllocationProtect is historical metadata; current Protect controls
     * classification. The old value must not create an executable finding.
     */
    MemoryRegion changed = makeRegion(PAGE_READONLY, MEM_PRIVATE);
    changed.allocationProtection = PAGE_EXECUTE_READWRITE;
    require(!classifyMemoryExposure(changed).executable, "Allocation protection used as current protection");

    // An empty collection must leave the checked counters at their zero defaults.
    require(calculateAuditMetrics({}).high == 0 && calculateMemoryStatistics({}).committedBytes == 0,
            "Empty scan produced findings");
}


// ============================================================
// REPORTING CHECKS
// ============================================================

/*
 * ConsoleCapture
 *
 * Temporarily redirects std::cout into an in-memory string stream.
 * This allows tests to inspect reports without filling the console.
 *
 * The original stream buffer is restored when the object leaves
 * scope, including when require() throws. Each capture scope
 * isolates one report so earlier output cannot satisfy a later check.
 */
class ConsoleCapture
{
public:
    ConsoleCapture() : previous_(std::cout.rdbuf(output_.rdbuf())) {}
    ~ConsoleCapture() { std::cout.rdbuf(previous_); }
    std::string text() const { return output_.str(); }

private:
    // Declare the destination first so it exists before redirecting std::cout.
    std::ostringstream output_;
    // This pointer is borrowed; the capture does not own the original buffer.
    std::streambuf* previous_;
};

/*
 * testReporting()
 *
 * Checks user-visible wording as well as classification results.
 * Filtered output must preserve guard information, and incomplete
 * scans must not imply complete coverage or external write access.
 */
void testReporting()
{
    // Simulate collected regions from a scan interrupted by an access error.
    ScanResult result{};
    result.status = ScanStatus::Partial;
    result.errorCode = ERROR_ACCESS_DENIED;
    result.failureAddress = 0x50000;
    result.regions =
    {
        makeRegion(PAGE_EXECUTE_READWRITE | PAGE_GUARD, MEM_PRIVATE),
        makeRegion(PAGE_EXECUTE_WRITECOPY, MEM_IMAGE, 0x20000)
    };

    // Only guarded private RWX belongs in the ordinary W+X display filter.
    {
        ConsoleCapture capture;
        displayMemoryRegions(result.regions, DisplayFilter::WritableExecutable);
        std::string text = capture.text();
        // find() returns npos when the expected wording is absent.
        require(text.find("[HIGH] Private W+X") != std::string::npos, "Private W+X row missing");
        require(text.find("guarded; base permissions shown") != std::string::npos, "Guard caveat missing");
        require(text.find("[LOW] Executable copy-on-write") == std::string::npos,
                "COW row leaked into ordinary W+X filter");
        require(text.find("Displayed regions: 1 / 2") != std::string::npos, "Filtered row count mismatch");
    }

    // A partial scan still reports observed totals, accompanied by a warning.
    {
        ConsoleCapture capture;
        displayAuditSummary(result, calculateMemoryStatistics(result.regions),
                            calculateAuditMetrics(result.regions));
        std::string text = capture.text();
        require(text.find("Scan status: PARTIAL") != std::string::npos &&
                text.find("Memory statistics may be incomplete") != std::string::npos,
                "Partial scan presented as complete");
        require(text.find("External write access: NOT ASSESSED") != std::string::npos,
                "External access limitation missing");
    }

    /*
     * Simulate a WOW64 target rejecting an address below the chosen ceiling.
     * This tests report wording only; it does not run a live 32-bit target
     * or exercise the enumeration code's boundary detection.
     *
     * ERROR_INVALID_PARAMETER alone must not be presented as proof that
     * the entire target address space was successfully inspected.
     */
    {
        result.targetWow64 = true;
        result.maximumAddress = 0xFFFFFFFF;
        result.errorCode = ERROR_INVALID_PARAMETER;
        ConsoleCapture capture;
        displayAuditSummary(result, calculateMemoryStatistics(result.regions),
                            calculateAuditMetrics(result.regions));
        require(capture.text().find("Completion could not be established") != std::string::npos &&
                capture.text().find("Scan status: PARTIAL") != std::string::npos,
                "WOW64 boundary error was presented as complete");
    }
}


// ============================================================
// CONTROLLED WINDOWS MEMORY FIXTURES
// ============================================================

/*
 * MemoryFixture
 *
 * Owns one real allocation for the lifetime of a live test.
 * The mapping argument selects a COW view instead of VirtualAlloc.
 *
 * Scope-based cleanup keeps the fixture alive throughout enumeration
 * and releases it even when a test check throws an exception.
 */
class MemoryFixture
{
public:
    explicit MemoryFixture(DWORD protection, bool mapping = false)
        : mapping_(mapping)
    {
        // Use the actual page size instead of the synthetic tests' fixed size.
        SYSTEM_INFO info{};
        GetSystemInfo(&info);

        if (mapping_)
        {
            /*
             * COW requires a mapped view; VirtualAlloc does not
             * support PAGE_WRITECOPY or PAGE_EXECUTE_WRITECOPY.
             * An executable mapping is used only for metadata tests.
             */
            /*
             * INVALID_HANDLE_VALUE creates a paging-file-backed mapping,
             * not a mapping of an on-disk file. The maximum protection
             * permits a copy view with the requested execute capability.
             */
            bool executable = isExecutable(protection);
            HANDLE fileMapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr,
                executable ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE,
                0, info.dwPageSize, nullptr);
            require(fileMapping != nullptr, "CreateFileMapping failed");
            // The mapping handle and the mapped view have separate lifetimes.
            WindowsHandle owner(fileMapping);
            /*
             * FILE_MAP_COPY requests a copy-on-write view.
             * FILE_MAP_EXECUTE additionally permits execute access.
             * The view remains valid after the mapping handle is closed
             * at the end of this branch; the destructor unmaps the view.
             */
            address_ = MapViewOfFile(fileMapping,
                FILE_MAP_COPY | (executable ? FILE_MAP_EXECUTE : 0), 0, 0, info.dwPageSize);
        }
        else
        {
            /*
             * Reserve an address range and commit its backing in one call.
             * A null address lets Windows choose the allocation location.
             * These allocations are reported as MEM_PRIVATE regions.
             */
            address_ = VirtualAlloc(nullptr, info.dwPageSize,
                                   MEM_RESERVE | MEM_COMMIT, protection);
        }

        // Do not continue with a null address that cannot represent a fixture.
        require(address_ != nullptr, "Controlled allocation failed");
    }

    /*
     * Each allocation API has a matching release API.
     * MEM_RELEASE requires the original allocation address and zero size.
     * A mapped view must instead be released with UnmapViewOfFile().
     */
    ~MemoryFixture()
    {
        if (mapping_)
            UnmapViewOfFile(address_);
        else
            VirtualFree(address_, 0, MEM_RELEASE);
    }

    // Prevent copies from trying to release the same allocation twice.
    MemoryFixture(const MemoryFixture&) = delete;
    MemoryFixture& operator=(const MemoryFixture&) = delete;

    // Return an integer address for range comparisons without reading contents.
    std::uintptr_t address() const { return reinterpret_cast<std::uintptr_t>(address_); }

private:
    bool mapping_ = false;
    void* address_ = nullptr;
};

/*
 * testLiveEnumeration()
 *
 * Scans this test process through a query-only handle, using the same
 * enumeration function as the auditor. Known allocations must appear
 * with their expected categories in the collected committed regions.
 */
void testLiveEnumeration()
{
    // Keep all six owners in scope so their allocations survive the scan.
    MemoryFixture writable(PAGE_READWRITE);
    MemoryFixture executable(PAGE_EXECUTE_READ);
    MemoryFixture writableExecutable(PAGE_EXECUTE_READWRITE);
    MemoryFixture guarded(PAGE_EXECUTE_READWRITE | PAGE_GUARD);
    MemoryFixture copyOnWrite(PAGE_WRITECOPY, true);
    MemoryFixture executableCopyOnWrite(PAGE_EXECUTE_WRITECOPY, true);

    /*
     * Open a real handle rather than using GetCurrentProcess()'s pseudohandle.
     * Request exactly the query right used by ProcessScanner; no memory-read,
     * memory-write, or memory-operation rights are needed for these queries.
     */
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    require(process != nullptr, "Query-only process open failed");
    WindowsHandle owner(process);
    ScanResult result = enumerateMemoryRegions(process);
    require(result.status == ScanStatus::Complete, "Controlled x64 process scan incomplete");

    // Match each allocation to its expected category using parallel arrays.
    const MemoryFixture* fixtures[] =
        {&writable, &executable, &writableExecutable, &guarded, &copyOnWrite, &executableCopyOnWrite};
    const ExposureCategory categories[] =
    {
        ExposureCategory::Writable, ExposureCategory::PrivateExecutable,
        ExposureCategory::PrivateWritableExecutable, ExposureCategory::PrivateWritableExecutable,
        ExposureCategory::CopyOnWrite, ExposureCategory::ExecutableCopyOnWrite
    };

    for (std::size_t index = 0; index < 6; index++)
    {
        std::uintptr_t address = fixtures[index]->address();
        /*
         * A queried region may contain the allocation address without
         * starting exactly at it. Search for address containment.
         *
         * Check address >= base first to avoid unsigned subtraction
         * underflow. Comparing the offset with regionSize also avoids
         * computing a potentially overflowing end address.
         */
        auto found = std::find_if(result.regions.begin(), result.regions.end(),
            [address](const MemoryRegion& region)
            {
                return address >= region.baseAddress && address - region.baseAddress < region.regionSize;
            });
        require(found != result.regions.end(), "Controlled allocation not collected");
        require(classifyMemoryExposure(*found).category == categories[index],
                "Real Windows allocation classification mismatch");
    }

    /*
     * Re-query the guarded fixture after enumeration.
     * Its guard must still be present: querying metadata should not
     * trigger the one-time access alarm by touching the guarded page.
     */
    MEMORY_BASIC_INFORMATION info{};
    require(VirtualQueryEx(process, reinterpret_cast<LPCVOID>(guarded.address()), &info, sizeof(info)) != 0 &&
            (info.Protect & PAGE_GUARD) != 0, "Scan consumed the guard modifier");

    /*
     * The loaded test executable provides genuine MEM_IMAGE memory.
     * Its module base is usually a header region, so the first query
     * verifies type only. Separately check that enumeration collected
     * at least one executable image region in the process.
     */
    require(VirtualQueryEx(process, GetModuleHandleW(nullptr), &info, sizeof(info)) != 0 &&
            info.Type == MEM_IMAGE, "Executable image fixture missing");
    require(std::any_of(result.regions.begin(), result.regions.end(), [](const MemoryRegion& region)
        { return region.type == MEM_IMAGE && isExecutable(region.protection); }),
        "Image executable regions not collected");

    // Invalid caller input must produce a failed scan instead of a success.
    require(enumerateMemoryRegions(nullptr).status == ScanStatus::Failed,
            "Null process handle accepted");
}


// ============================================================
// TEST PROGRAM ENTRY POINT
// ============================================================

/*
 * main()
 *
 * Runs deterministic checks before the live Windows API checks.
 * A failed require() stops the remaining tests and reports its message.
 *
 * Exit Codes:
 *   0 - Every check completed successfully.
 *   1 - A check or standard-library operation threw an exception.
 *
 * CTest uses these exit codes to mark the test as passed or failed.
 */
int main()
{
    try
    {
        testPermissions();
        testAnalysis();
        testReporting();
        testLiveEnumeration();
        std::cout << "All memory exposure checks passed.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        // Stack unwinding restores captured output and releases fixture resources.
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
