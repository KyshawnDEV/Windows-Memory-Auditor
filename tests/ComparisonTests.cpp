#include "ScanComparison.h"
#include "MemoryScanner.h"
#include "WindowsHandle.h"

#include <algorithm>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * ComparisonTests.cpp
 *
 * Verifies v0.7 comparisons using both predictable metadata and
 * controlled changes to this test process's own memory.
 *
 * Test Groups:
 *   - Added/removed ranges and changed permissions/categories/priorities
 *   - Region splits, merges, and allocation metadata differences
 *   - Incomplete coverage, process identity, and invalid records
 *   - Complete-baseline retention and bounded session history
 *   - Timing, report wording, and live query-only snapshots
 *
 * Tests change only their own fixtures and never execute fixture code.
 * The auditor's capture path remains query-only.
 */

// ============================================================
// TEST HELPERS
// ============================================================

/*
 * require()
 *
 * Throws an explanation when a checked expectation is false.
 * It stays active in Debug and Release builds. main() reports
 * the first failure and returns the nonzero exit code used by CTest.
 */
void require(bool condition, const std::string& message)
{
    if (!condition)
        throw std::runtime_error(message);
}

/*
 * makeRegion() / makeSnapshot()
 *
 * Create synthetic metadata without allocating or accessing memory.
 * Default identity and scan bounds make two snapshots comparable.
 * Tests explicitly change those defaults when exercising rejection
 * or incomplete-coverage cases. Addresses are labels only.
 */
MemoryRegion makeRegion(std::uintptr_t address, DWORD protection,
    SIZE_T size = 4096, DWORD type = MEM_PRIVATE, std::uintptr_t allocationBase = 0x10000)
{
    MemoryRegion region{};
    region.baseAddress = address;
    region.allocationBase = allocationBase;
    region.regionSize = size;
    region.state = MEM_COMMIT;
    region.protection = protection;
    region.allocationProtection = PAGE_READWRITE;
    region.type = type;
    return region;
}

ScanSnapshot makeSnapshot(std::vector<MemoryRegion> regions)
{
    ScanSnapshot snapshot{};
    snapshot.pid = 123;
    snapshot.processCreationTime = 42;
    snapshot.identityKnown = true;
    snapshot.memory.status = ScanStatus::Complete;
    snapshot.memory.minimumAddress = 0x10000;
    snapshot.memory.maximumAddress = 0xFFFFFF;
    snapshot.memory.regions = std::move(regions);
    return snapshot;
}

// Count changed address ranges, not queried rows or assumed OS events.
std::size_t countKind(const ScanComparison& comparison, RegionChangeKind kind)
{
    return static_cast<std::size_t>(std::count_if(comparison.changes.begin(), comparison.changes.end(),
        [kind](const RegionChange& change) { return change.kind == kind; }));
}

/*
 * changeAt()
 *
 * Find the comparison interval containing an address. A difference
 * may affect a subset of a queried region after a protection split.
 * Offset comparisons avoid overflowing an end-address calculation.
 */
const RegionChange& changeAt(const ScanComparison& comparison, std::uintptr_t address)
{
    auto found = std::find_if(comparison.changes.begin(), comparison.changes.end(),
        [address](const RegionChange& change)
        {
            return address >= change.baseAddress && address - change.baseAddress < change.regionSize;
        });
    require(found != comparison.changes.end(), "Expected changed address range missing");
    return *found;
}

// Scope cleanup restores normal output even when an assertion throws.
class ConsoleCapture
{
public:
    ConsoleCapture() : previous_(std::cout.rdbuf(output_.rdbuf())) {}
    ~ConsoleCapture() { std::cout.rdbuf(previous_); }
    std::string text() const { return output_.str(); }

private:
    std::ostringstream output_;
    std::streambuf* previous_;
};


// ============================================================
// BASIC OBSERVED DIFFERENCES
// ============================================================

void testDifferences()
{
    ScanSnapshot before = makeSnapshot({
        makeRegion(0x10000, PAGE_READWRITE),
        makeRegion(0x20000, PAGE_EXECUTE_READ),
        makeRegion(0x30000, PAGE_READWRITE)
    });
    ScanSnapshot after = makeSnapshot({
        makeRegion(0x10000, PAGE_EXECUTE_READWRITE),
        makeRegion(0x30000, PAGE_READWRITE),
        makeRegion(0x50000, PAGE_EXECUTE_READ, 4096, MEM_PRIVATE, 0x50000)
    });
    ScanComparison comparison = compareMemorySnapshots(before, after);

    /*
     * The shared first range changes from writable data to private W+X.
     * The second range disappears from complete committed coverage.
     * The final range appears where complete prior coverage had no commit.
     * The unchanged middle range must not generate a difference.
     */
    require(comparison.status == ComparisonStatus::Compared && comparison.changes.size() == 3,
            "Basic comparison produced unexpected differences");
    const RegionChange& attributes = changeAt(comparison, 0x10000);
    require(attributes.kind == RegionChangeKind::AttributesChanged && attributes.protectionChanged &&
            attributes.exposureChanged && attributes.priorityChanged,
            "Protection, exposure, or priority difference omitted");
    require(changeAt(comparison, 0x20000).kind == RegionChangeKind::Removed &&
            changeAt(comparison, 0x50000).kind == RegionChangeKind::Added,
            "Added/removed committed ranges incorrect");

    // Input order is not identity; normalizing order must preserve the result.
    std::reverse(before.memory.regions.begin(), before.memory.regions.end());
    std::reverse(after.memory.regions.begin(), after.memory.regions.end());
    require(compareMemorySnapshots(before, after).changes.size() == 3,
            "Unsorted snapshot changed comparison results");

    // A guard modifier changes raw protection without changing base exposure or priority.
    before = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READ)});
    after = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READ | PAGE_GUARD)});
    comparison = compareMemorySnapshots(before, after);
    require(comparison.changes.size() == 1 && comparison.changes[0].protectionChanged &&
            !comparison.changes[0].exposureChanged && !comparison.changes[0].priorityChanged,
            "Guard-only change was ignored or confused with a base permission change");

    // COW and ordinary W+X remain distinct when comparing observed metadata.
    before = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_WRITECOPY, 4096, MEM_MAPPED)});
    after = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READWRITE, 4096, MEM_MAPPED)});
    comparison = compareMemorySnapshots(before, after);
    require(comparison.changes.size() == 1 && comparison.changes[0].exposureChanged &&
            comparison.changes[0].priorityChanged, "Executable COW/W+X difference missing");
}


// ============================================================
// SPLITS, MERGES, AND ALLOCATION CONTINUITY
// ============================================================

void testBoundariesAndMetadata()
{
    ScanSnapshot whole = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE, 12288)});
    ScanSnapshot split = makeSnapshot({
        makeRegion(0x10000, PAGE_READWRITE),
        makeRegion(0x11000, PAGE_EXECUTE_READ),
        makeRegion(0x12000, PAGE_READWRITE)
    });
    ScanComparison comparison = compareMemorySnapshots(whole, split);

    /*
     * VirtualProtect on a middle page can split one queried row into three.
     * The address coverage is unchanged. Only the middle interval differs;
     * it must not become three additions and one removal.
     */
    require(comparison.changes.size() == 1 && comparison.changes[0].baseAddress == 0x11000 &&
            comparison.changes[0].regionSize == 4096 &&
            comparison.changes[0].kind == RegionChangeKind::AttributesChanged,
            "Region split produced false additions/removals");
    require(compareMemorySnapshots(split, whole).changes.size() == 1,
            "Region merge produced false additions/removals");
    split.memory.regions[1].protection = PAGE_READWRITE;
    require(compareMemorySnapshots(whole, split).changes.empty(),
            "Row boundary changes alone were treated as metadata differences");

    // A shifted committed interval has one removed prefix and one added suffix.
    whole = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE, 8192)});
    split = makeSnapshot({makeRegion(0x11000, PAGE_READWRITE, 8192)});
    comparison = compareMemorySnapshots(whole, split);
    require(comparison.changes.size() == 2 && countKind(comparison, RegionChangeKind::Added) == 1 &&
            countKind(comparison, RegionChangeKind::Removed) == 1,
            "Partial overlap did not preserve shared committed coverage");

    /*
     * Reused addresses can have different allocation metadata.
     * The report must distinguish that from attributing a protection
     * transition to one proven allocation lifetime.
     */
    whole = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READ)});
    split = whole;
    split.memory.regions[0].allocationBase = 0xF000;
    comparison = compareMemorySnapshots(whole, split);
    require(comparison.changes.size() == 1 &&
            comparison.changes[0].kind == RegionChangeKind::AllocationMetadataChanged,
            "Changed allocation base was treated as verified continuity");

    split = whole;
    split.memory.regions[0].allocationProtection = PAGE_EXECUTE_READWRITE;
    require(compareMemorySnapshots(whole, split).changes[0].kind == RegionChangeKind::AllocationMetadataChanged,
            "Original allocation protection difference ignored");

    split = whole;
    split.memory.regions[0].type = MEM_IMAGE;
    comparison = compareMemorySnapshots(whole, split);
    require(comparison.changes[0].kind == RegionChangeKind::AllocationMetadataChanged &&
            comparison.changes[0].exposureChanged && comparison.changes[0].priorityChanged,
            "Changed memory type or derived priority difference missing");

    // Identical sampled metadata cannot reveal an unobserved release/reallocation.
    require(compareMemorySnapshots(whole, whole).changes.empty(),
            "Identical samples generated an invented allocation-lifetime event");
}


// ============================================================
// COVERAGE, IDENTITY, AND VALIDATION
// ============================================================

void testCoverageAndIdentity()
{
    ScanSnapshot before = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE), makeRegion(0x20000, PAGE_READWRITE)});
    ScanSnapshot after = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READWRITE),
        makeRegion(0x25000, PAGE_READWRITE)});
    after.memory.status = ScanStatus::Partial;
    after.memory.failureAddress = 0x30000;
    ScanComparison comparison = compareMemorySnapshots(before, after);

    /*
     * A partial current scan can positively observe an attribute change
     * or a range absent from a complete baseline. Its missing ranges
     * must stay unobserved, even if their addresses precede the failure.
     * No negative evidence is inferred from partial scan coverage.
     */
    require(countKind(comparison, RegionChangeKind::Removed) == 0 &&
            countKind(comparison, RegionChangeKind::UnobservedInCurrent) == 1 &&
            countKind(comparison, RegionChangeKind::Added) == 1,
            "Partial current scan generated a false removal");

    before = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE)});
    before.memory.status = ScanStatus::Partial;
    after = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE), makeRegion(0x20000, PAGE_READWRITE)});
    comparison = compareMemorySnapshots(before, after);
    require(countKind(comparison, RegionChangeKind::Added) == 0 &&
            countKind(comparison, RegionChangeKind::UnobservedInPrevious) == 1,
            "Partial prior coverage generated a false addition");

    // Even complete absence evidence is limited to the prior scan's recorded bounds.
    before.memory.status = ScanStatus::Complete;
    before.memory.maximumAddress = 0x1FFFF;
    comparison = compareMemorySnapshots(before, after);
    require(countKind(comparison, RegionChangeKind::Added) == 0,
            "Range outside prior bounds was classified as added");

    before = makeSnapshot({});
    after = before;
    after.processCreationTime++;
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::DifferentProcess,
            "PID reuse was compared as the same process instance");
    after = before;
    after.pid++;
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::DifferentProcess,
            "Different PIDs were compared");
    after = before;
    after.identityKnown = false;
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::IdentityUnavailable,
            "Unverified process identity accepted");
    after = before;
    after.memory.status = ScanStatus::Failed;
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::FailedScan,
            "Failed scan was compared as an empty complete address space");

    // Reject overlapping intervals and overflowing endpoints rather than inventing differences.
    before = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE, 8192), makeRegion(0x11000, PAGE_READWRITE)});
    after = makeSnapshot({});
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::InvalidRegionData,
            "Overlapping committed records accepted");
    before = makeSnapshot({makeRegion(std::numeric_limits<std::uintptr_t>::max() - 100, PAGE_READWRITE, 4096)});
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::InvalidRegionData,
            "Overflowing interval accepted");
    before = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE, 0)});
    require(compareMemorySnapshots(before, after).status == ComparisonStatus::InvalidRegionData,
            "Zero-sized interval accepted");
    require(compareMemorySnapshots(after, after).changes.empty(), "Two empty complete scans invented changes");

    // Adjacent equal changes should coalesce even if queried row boundaries differ.
    before = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE, 8192)});
    after = makeSnapshot({makeRegion(0x10000, PAGE_EXECUTE_READ), makeRegion(0x11000, PAGE_EXECUTE_READ)});
    comparison = compareMemorySnapshots(before, after);
    require(comparison.changes.size() == 1 && comparison.changes[0].regionSize == 8192,
            "Adjacent identical changes inflated the change count");
}


// ============================================================
// BASELINE RETENTION AND REPORTING
// ============================================================

void testHistoryAndReports()
{
    ScanHistory history;
    ScanSnapshot baseline = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE)});
    require(history.remember(baseline), "Complete baseline not retained");
    ScanSnapshot partial = baseline;
    partial.memory.status = ScanStatus::Partial;
    partial.memory.regions[0].protection = PAGE_EXECUTE_READWRITE;
    require(!history.remember(partial) && history.find(123)->memory.regions[0].protection == PAGE_READWRITE,
            "Partial scan replaced a complete baseline");
    partial.memory.status = ScanStatus::Failed;
    require(!history.remember(partial), "Failed scan retained as baseline");
    partial = baseline;
    partial.identityKnown = false;
    require(!history.remember(partial), "Unknown identity retained as baseline");
    partial = baseline;
    partial.memory.regions[0].regionSize = 0;
    require(!history.remember(partial), "Invalid region data retained as baseline");

    /*
     * Retain eight targets, refresh the oldest, then add a ninth.
     * The least recently updated target is evicted, while the refreshed
     * baseline stays available. This bounds session memory usage by count.
     */
    ScanHistory bounded;
    for (DWORD pid = 1; pid <= ScanHistory::MAX_BASELINES; pid++)
    {
        baseline.pid = pid;
        require(bounded.remember(baseline), "Baseline setup failed");
    }
    baseline.pid = 1;
    bounded.remember(baseline);
    baseline.pid = static_cast<DWORD>(ScanHistory::MAX_BASELINES + 1);
    bounded.remember(baseline);
    require(bounded.find(1) != nullptr && bounded.find(2) == nullptr && bounded.find(baseline.pid) != nullptr,
            "History did not evict the least recently updated target");

    // A fixed UTC fixture verifies timestamp formatting independent of the host timezone.
    SYSTEMTIME time{};
    time.wYear = 2020;
    time.wMonth = 1;
    time.wDay = 2;
    time.wHour = 3;
    time.wMinute = 4;
    time.wSecond = 5;
    time.wMilliseconds = 6;
    FILETIME encoded{};
    require(SystemTimeToFileTime(&time, &encoded) != 0 &&
            scanTimeToString(encoded) == "2020-01-02 03:04:05.006 UTC",
            "Scan timestamp formatting incorrect");

    baseline = makeSnapshot({makeRegion(0x10000, PAGE_READWRITE)});
    baseline.startedAt = encoded;
    ScanSnapshot current = baseline;
    current.memory.regions[0].protection = PAGE_EXECUTE_READWRITE;
    ScanComparison comparison = compareMemorySnapshots(baseline, current);

    {
        ConsoleCapture capture;
        displayScanTiming(current);
        displayScanComparison(baseline, current, comparison);
        std::string text = capture.text();
        require(text.find("PID + creation time verified") != std::string::npos &&
                text.find("Protection / exposure / priority differences: 1 / 1 / 1") != std::string::npos &&
                text.find("do not prove allocation continuity") != std::string::npos &&
                text.find("intermediate changes and causality are unknown") != std::string::npos,
                "Timing, difference counts, or comparison limitations missing");
    }

    current.processCreationTime++;
    {
        ConsoleCapture capture;
        displayScanComparison(baseline, current, compareMemorySnapshots(baseline, current));
        require(capture.text().find("different process instance") != std::string::npos,
                "PID reuse rejection missing from report");
    }
}


// ============================================================
// LIVE CONTROLLED MEMORY CHANGES
// ============================================================

/*
 * MemoryFixture
 *
 * Keeps a reservation alive while individual pages are committed,
 * protected, or decommitted. A retained reservation prevents the test
 * allocator from reusing a removed range during the next snapshot.
 * Scope cleanup releases the entire fixture after all comparisons.
 */
class MemoryFixture
{
public:
    MemoryFixture(std::size_t pages, bool commit)
    {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        pageSize_ = info.dwPageSize;
        size_ = pageSize_ * pages;
        address_ = VirtualAlloc(nullptr, size_, MEM_RESERVE, PAGE_READWRITE);
        require(address_ != nullptr, "Live reservation failed");

        if (commit && VirtualAlloc(address_, size_, MEM_COMMIT, PAGE_READWRITE) == nullptr)
        {
            // A constructor that throws does not run its own destructor.
            VirtualFree(address_, 0, MEM_RELEASE);
            throw std::runtime_error("Live fixture commitment failed");
        }
    }

    ~MemoryFixture() { VirtualFree(address_, 0, MEM_RELEASE); }
    MemoryFixture(const MemoryFixture&) = delete;
    MemoryFixture& operator=(const MemoryFixture&) = delete;
    std::uintptr_t base() const { return reinterpret_cast<std::uintptr_t>(address_); }
    SIZE_T pageSize() const { return pageSize_; }

    void protectMiddle()
    {
        DWORD oldProtection = 0;
        require(VirtualProtect(static_cast<char*>(address_) + pageSize_, pageSize_, PAGE_EXECUTE_READ, &oldProtection),
                "Live protection change failed");
    }

    void commitExecutable()
    {
        require(VirtualAlloc(address_, size_, MEM_COMMIT, PAGE_EXECUTE_READWRITE) != nullptr,
                "Live executable commitment failed");
    }

    void decommit()
    {
        require(VirtualFree(address_, size_, MEM_DECOMMIT), "Live fixture decommit failed");
    }

private:
    void* address_ = nullptr;
    SIZE_T pageSize_ = 0;
    SIZE_T size_ = 0;
};

void testLiveComparison()
{
    MemoryFixture changed(3, true);
    MemoryFixture added(1, false);
    MemoryFixture removed(1, true);
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    require(process != nullptr, "Live query-only handle unavailable");
    WindowsHandle owner(process);
    ScanSnapshot before = captureMemorySnapshot(process);

    /*
     * The reserved-only fixture becomes committed W+X.
     * One already committed allocation gains an RX middle page.
     * Another fixture becomes reserved-only through decommit.
     * These are test setup actions, not operations performed by the scanner.
     */
    changed.protectMiddle();
    added.commitExecutable();
    removed.decommit();
    ScanSnapshot after = captureMemorySnapshot(process);
    require(before.identityKnown && after.identityKnown && before.processCreationTime == after.processCreationTime &&
            before.pid == after.pid, "Live process identity not preserved");
    require(before.memory.status == ScanStatus::Complete && after.memory.status == ScanStatus::Complete,
            "Live comparison snapshot incomplete");
    require(scanTimeToString(before.startedAt) != "Unavailable" &&
            scanTimeToString(after.completedAt) != "Unavailable", "Live scan timing missing");
    ScanComparison comparison = compareMemorySnapshots(before, after);

    // Other process regions can change during self-scanning; assert only the controlled addresses.
    const RegionChange& protection = changeAt(comparison, changed.base() + changed.pageSize());
    require(protection.kind == RegionChangeKind::AttributesChanged && protection.regionSize == changed.pageSize() &&
            protection.before->protection == PAGE_READWRITE && protection.after->protection == PAGE_EXECUTE_READ &&
            protection.exposureChanged && protection.priorityChanged, "Live split protection difference incorrect");
    require(changeAt(comparison, added.base()).kind == RegionChangeKind::Added,
            "Live commitment was not observed as an added committed range");
    require(changeAt(comparison, removed.base()).kind == RegionChangeKind::Removed,
            "Live decommit was not observed as a removed committed range");
    ScanSnapshot invalid = captureMemorySnapshot(nullptr);
    require(!invalid.identityKnown && invalid.memory.status == ScanStatus::Failed,
            "Invalid handle produced a comparable live snapshot");
}


// ============================================================
// TEST PROGRAM ENTRY POINT
// ============================================================

int main()
{
    try
    {
        testDifferences();
        testBoundariesAndMetadata();
        testCoverageAndIdentity();
        testHistoryAndReports();
        testLiveComparison();
        std::cout << "All repeated-scan comparison checks passed.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
