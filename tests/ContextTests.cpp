#include "MemoryContext.h"
#include "MemoryScanner.h"
#include "WindowsHandle.h"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * ContextTests.cpp
 *
 * Verifies v0.6 allocation grouping, module association, and
 * context reporting without changing the v0.5 exposure policy.
 *
 * Synthetic records provide deterministic grouping and failure cases.
 * Real Windows fixtures verify AllocationBase, loader snapshots,
 * and mapped-file paths through a query-only process handle.
 *
 * The tests never execute their allocated memory. Fixture owners
 * release allocations and views when a test passes or throws.
 */

// ============================================================
// TEST HELPERS
// ============================================================

/*
 * require()
 *
 * Checks an expectation and throws its explanation on failure.
 * These checks remain enabled in Release builds, unlike assert().
 * main() converts the first failure into a nonzero CTest exit code.
 */
void require(bool condition, const std::string& message)
{
    if (!condition)
        throw std::runtime_error(message);
}

/*
 * makeRegion()
 *
 * Creates synthetic metadata, not an actual memory allocation.
 * AllocationBase identifies the group, while BaseAddress identifies
 * one protection range within that allocation. Addresses are labels
 * only and must never be dereferenced by these synthetic tests.
 */
MemoryRegion makeRegion(std::uintptr_t base, std::uintptr_t allocationBase,
    DWORD protection, DWORD type)
{
    MemoryRegion region{};
    region.baseAddress = base;
    region.allocationBase = allocationBase;
    region.regionSize = 4096;
    region.state = MEM_COMMIT;
    region.protection = protection;
    region.type = type;
    return region;
}

/*
 * ConsoleCapture
 *
 * Redirects std::cout into a string stream while one report is printed.
 * Scope cleanup restores the original buffer, including after an exception.
 * This tests visible context wording without printing each report to CTest.
 */
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

std::size_t countOccurrences(const std::string& text, const std::string& marker)
{
    std::size_t count = 0;
    std::size_t position = 0;

    while ((position = text.find(marker, position)) != std::string::npos)
    {
        count++;
        position += marker.size();
    }

    return count;
}


// ============================================================
// ALLOCATION GROUPING CHECKS
// ============================================================

void testGrouping()
{
    /*
     * The first two ranges share an allocation but leave a gap.
     * Group size must sum committed bytes rather than span that gap.
     * A separate allocation prevents grouping by proximity or type.
     */
    std::vector<MemoryRegion> regions =
    {
        makeRegion(0x10000, 0x10000, PAGE_READWRITE, MEM_PRIVATE),
        makeRegion(0x14000, 0x10000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
        makeRegion(0x20000, 0x20000, PAGE_EXECUTE_READ, MEM_PRIVATE)
    };

    auto groups = groupMemoryAllocations(regions);
    require(groups.size() == 2, "Ranges sharing AllocationBase were not grouped");
    require(groups[0].regionIndices == std::vector<std::size_t>({0, 1}),
            "Grouping lost original region indices");
    require(groups[0].committedBytes == 8192 && groups[0].executableRegions == 1 &&
            groups[0].writableExecutableRegions == 1, "Grouping counted a gap or lost permissions");
    require(groups[0].priority == InvestigationPriority::High &&
            groups[1].priority == InvestigationPriority::Medium, "Highest group priority incorrect");
    require(groups[0].mappedFileStatus == MappedFileStatus::NotApplicable,
            "Private allocation requested file context");

    /*
     * Metadata from older or external callers may lack AllocationBase.
     * Two such records must remain independent, including when their
     * synthetic BaseAddress values happen to be equal.
     */
    regions.push_back(makeRegion(0x30000, 0, PAGE_READWRITE, MEM_PRIVATE));
    regions.push_back(makeRegion(0x30000, 0, PAGE_READWRITE, MEM_PRIVATE));
    MemoryRegion reserved = makeRegion(0x40000, 0x40000, PAGE_NOACCESS, MEM_PRIVATE);
    reserved.state = MEM_RESERVE;
    regions.push_back(reserved);
    groups = groupMemoryAllocations(regions);
    require(groups.size() == 4 && !groups[2].allocationBaseKnown && !groups[3].allocationBaseKnown,
            "Missing allocation bases merged or reserved memory became a group");
    require(groupMemoryAllocations({}).empty(), "Empty collection produced allocation groups");
}


// ============================================================
// MODULE ASSOCIATION CHECKS
// ============================================================

void testModuleAssociation()
{
    std::vector<MemoryRegion> regions =
    {
        makeRegion(0x51000, 0x50000, PAGE_EXECUTE_READWRITE, MEM_IMAGE),
        makeRegion(0x53000, 0x50000, PAGE_READONLY, MEM_IMAGE),
        makeRegion(0x61000, 0x60000, PAGE_EXECUTE_READ, MEM_PRIVATE)
    };
    auto groups = groupMemoryAllocations(regions);
    ModuleSnapshot snapshot{};
    snapshot.status = ModuleSnapshotStatus::Complete;
    ModuleContext module{};
    module.baseAddress = 0x50000;
    module.imageSize = 0x5000;
    module.name = L"example.dll";
    module.path = L"C:\\Tests\\example.dll";
    snapshot.modules.push_back(module);

    // A module must match both the allocation base and all observed image ranges.
    associateAllocationModules(groups, regions, snapshot);
    require(groups[0].moduleStatus == ModuleAssociationStatus::Available &&
            groups[0].module.name == L"example.dll", "Matching image module not associated");
    require(groups[1].moduleStatus == ModuleAssociationStatus::NotApplicable,
            "Private executable memory was treated as a loader module");
    require(groups[0].priority == InvestigationPriority::Medium &&
            classifyMemoryExposure(regions[0]).priority == InvestigationPriority::Medium,
            "Module association reduced an image W+X priority");

    // A same-base module with an insufficient image range is not a valid match.
    snapshot.modules[0].imageSize = 0x2000;
    associateAllocationModules(groups, regions, snapshot);
    require(groups[0].moduleStatus == ModuleAssociationStatus::NotObserved &&
            groups[0].module.name.empty(), "Out-of-range or stale module association retained");

    /*
     * No match in a complete snapshot differs from unavailable metadata.
     * An access error must be retained as context failure, without changing
     * the already collected regions or their classification.
     */
    snapshot.modules.clear();
    snapshot.status = ModuleSnapshotStatus::Failed;
    snapshot.errorCode = ERROR_ACCESS_DENIED;
    associateAllocationModules(groups, regions, snapshot);
    require(groups[0].moduleStatus == ModuleAssociationStatus::Unavailable &&
            groups[0].moduleErrorCode == ERROR_ACCESS_DENIED, "Snapshot error was hidden");

    // Partial snapshots can still contain usable associations; incompleteness is reported separately.
    snapshot.status = ModuleSnapshotStatus::Partial;
    snapshot.modules.push_back(module);
    associateAllocationModules(groups, regions, snapshot);
    require(groups[0].moduleStatus == ModuleAssociationStatus::Available,
            "Known association from a partial snapshot was discarded");

    // Missing bases cannot be inferred from module range overlap alone.
    regions[0].allocationBase = 0;
    groups = groupMemoryAllocations(regions);
    associateAllocationModules(groups, regions, snapshot);
    require(groups[0].moduleStatus == ModuleAssociationStatus::Unavailable,
            "Unknown allocation base received a module association");
}


// ============================================================
// CONTEXT REPORTING CHECKS
// ============================================================

void testReporting()
{
    std::vector<MemoryRegion> regions =
    {
        makeRegion(0x10000, 0x10000, PAGE_EXECUTE_READWRITE, MEM_PRIVATE),
        makeRegion(0x11000, 0x10000, PAGE_EXECUTE_READ, MEM_PRIVATE),
        makeRegion(0x20000, 0x20000, PAGE_READWRITE, MEM_PRIVATE)
    };
    MemoryContext context{};
    context.allocations = groupMemoryAllocations(regions);

    {
        ConsoleCapture capture;
        displayMemoryRegions(regions, DisplayFilter::Executable, &context);
        std::string text = capture.text();
        require(countOccurrences(text, "[ALLOCATION]") == 1,
                "Allocation header repeated or appeared for a filtered-out group");
        require(text.find("Observed committed regions: 2 | Bytes: 8192") != std::string::npos &&
                text.find("Displayed regions: 2 / 3") != std::string::npos,
                "Context changed filter membership or lost group totals");
        require(text.find("origin is not established") != std::string::npos,
                "Private executable allocation was given an unsupported origin");
    }

    /*
     * Context totals remain based on all collected allocations.
     * An unavailable module snapshot is separate from the memory
     * scan status and must not be presented as an exposure finding.
     */
    context.moduleSnapshot.status = ModuleSnapshotStatus::Failed;
    context.moduleSnapshot.errorCode = ERROR_ACCESS_DENIED;

    {
        ConsoleCapture capture;
        displayMemoryContextSummary(context);
        require(capture.text().find("Observed allocation groups: 2") != std::string::npos &&
                capture.text().find("Module snapshot: UNAVAILABLE") != std::string::npos &&
                capture.text().find("unavailable context is not a finding") != std::string::npos,
                "Missing context warning or full-scan totals absent");
    }

    // Unicode and control characters must not be lost or create misleading extra report rows.
    AllocationContext unicode{};
    unicode.moduleStatus = ModuleAssociationStatus::Available;
    unicode.module.name = L"example\u03A9.dll";
    unicode.module.path = L"C:\\Tests\\line\nname.dll";
    unicode.module.pathMayBeTruncated = true;
    unicode.mappedFileStatus = MappedFileStatus::Unavailable;
    unicode.mappedFileErrorCode = ERROR_FILE_NOT_FOUND;

    {
        ConsoleCapture capture;
        displayAllocationContext(unicode);
        require(capture.text().find("example\\u03A9.dll") != std::string::npos &&
                capture.text().find("line\\u000Aname.dll") != std::string::npos &&
                capture.text().find("may be truncated") != std::string::npos &&
                capture.text().find("Mapped file: Unavailable") != std::string::npos,
                "Unicode, truncation, or missing mapped-file status not preserved");
    }

    require(exposureToString(ExposureCategory::None) == "No current write/execute permissions observed",
            "No-permission label implies a broader security conclusion");
}


// ============================================================
// LIVE WINDOWS CONTEXT FIXTURES
// ============================================================

/*
 * SplitAllocation
 *
 * Reserves five pages but commits only the first, second, and fifth.
 * The reserved gap verifies that allocation totals do not count it.
 * Different current protections force separate VirtualQueryEx ranges
 * belonging to the same original allocation.
 */
class SplitAllocation
{
public:
    SplitAllocation()
    {
        SYSTEM_INFO info{};
        GetSystemInfo(&info);
        pageSize_ = info.dwPageSize;
        address_ = VirtualAlloc(nullptr, pageSize_ * 5, MEM_RESERVE, PAGE_READWRITE);
        require(address_ != nullptr, "Reservation fixture failed");

        /*
         * A throwing constructor does not run its own destructor.
         * Release the reservation explicitly if any setup call fails.
         */
        bool committed = VirtualAlloc(address_, pageSize_ * 2, MEM_COMMIT, PAGE_READWRITE) != nullptr;
        committed = committed && VirtualAlloc(static_cast<char*>(address_) + pageSize_ * 4,
            pageSize_, MEM_COMMIT, PAGE_EXECUTE_READ) != nullptr;
        DWORD oldProtection = 0;
        bool protectedPage = committed && VirtualProtect(address_, pageSize_, PAGE_READONLY, &oldProtection);

        if (!protectedPage)
        {
            VirtualFree(address_, 0, MEM_RELEASE);
            throw std::runtime_error("Split protection fixture failed");
        }
    }

    ~SplitAllocation() { VirtualFree(address_, 0, MEM_RELEASE); }
    SplitAllocation(const SplitAllocation&) = delete;
    SplitAllocation& operator=(const SplitAllocation&) = delete;
    std::uintptr_t base() const { return reinterpret_cast<std::uintptr_t>(address_); }
    std::uint64_t committedBytes() const { return pageSize_ * 3; }

private:
    void* address_ = nullptr;
    std::uint64_t pageSize_ = 0;
};

/*
 * FileView
 *
 * Maps the on-disk test executable as ordinary readonly data.
 * This produces MEM_MAPPED memory with a genuine mapped-file path,
 * distinct from the executable's existing MEM_IMAGE loader mapping.
 * No bytes are read from either view by the test or context collector.
 */
class FileView
{
public:
    FileView()
    {
        std::vector<wchar_t> path(32768, L'\0');
        DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        require(length != 0 && length < path.size(), "Test executable path unavailable");
        path_ = std::wstring(path.data(), length);

        HANDLE file = CreateFileW(path_.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
        require(file != INVALID_HANDLE_VALUE, "Readonly file fixture open failed");
        WindowsHandle fileOwner(file);
        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        require(mapping != nullptr, "Readonly file mapping failed");
        WindowsHandle mappingOwner(mapping);
        address_ = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        require(address_ != nullptr, "Readonly mapped view failed");

        // The view stays valid after the two local handles are released.
    }

    ~FileView() { UnmapViewOfFile(address_); }
    FileView(const FileView&) = delete;
    FileView& operator=(const FileView&) = delete;
    std::uintptr_t base() const { return reinterpret_cast<std::uintptr_t>(address_); }

private:
    void* address_ = nullptr;
    std::wstring path_;
};

void testLiveContext()
{
    SplitAllocation split;
    FileView view;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    require(process != nullptr, "Query-only process open failed");
    WindowsHandle owner(process);

    ScanResult scan = enumerateMemoryRegions(process);
    require(scan.status == ScanStatus::Complete, "Live context memory walk incomplete");
    AuditMetrics before = calculateAuditMetrics(scan.regions);
    MemoryContext context = collectMemoryContext(process, scan.regions);
    AuditMetrics after = calculateAuditMetrics(scan.regions);
    require(before.high == after.high && before.medium == after.medium && before.low == after.low,
            "Context collection changed exposure counts");
    require(context.moduleSnapshot.status == ModuleSnapshotStatus::Complete,
            "Self-process module snapshot incomplete");

    auto findGroup = [&context](std::uintptr_t base) -> const AllocationContext&
    {
        auto found = std::find_if(context.allocations.begin(), context.allocations.end(),
            [base](const AllocationContext& allocation) { return allocation.allocationBase == base; });
        require(found != context.allocations.end(), "Live allocation group not found");
        return *found;
    };

    // Three committed protection ranges share one reservation and exclude its gap.
    const AllocationContext& splitGroup = findGroup(split.base());
    require(splitGroup.regionIndices.size() == 3 && splitGroup.committedBytes == split.committedBytes() &&
            splitGroup.type == MEM_PRIVATE && splitGroup.moduleStatus == ModuleAssociationStatus::NotApplicable,
            "Live split allocation grouping incorrect");

    // The loader's executable mapping should have both module and backing-file context.
    const AllocationContext& imageGroup = findGroup(reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)));
    require(imageGroup.type == MEM_IMAGE && imageGroup.moduleStatus == ModuleAssociationStatus::Available &&
            imageGroup.mappedFileStatus == MappedFileStatus::Available && !imageGroup.module.name.empty(),
            "Live image association or mapped-file path missing");

    // Ordinary file data is mapped memory, not a loader module or trusted executable.
    const AllocationContext& fileGroup = findGroup(view.base());
    require(fileGroup.type == MEM_MAPPED && fileGroup.moduleStatus == ModuleAssociationStatus::NotApplicable &&
            fileGroup.mappedFileStatus == MappedFileStatus::Available && !fileGroup.mappedFilePath.empty(),
            "Live readonly file mapping context missing");
    require(fileGroup.mappedFilePath == imageGroup.mappedFilePath,
            "Two mappings of the same executable produced different backing-file paths");

    /*
     * Deliberately fail context lookup while retaining synthetic memory.
     * This checks explicit failure reporting without depending on elevated
     * privileges or opening a protected system process.
     */
    std::vector<MemoryRegion> image = {makeRegion(0x51000, 0x50000, PAGE_EXECUTE_READ, MEM_IMAGE)};
    MemoryContext unavailable = collectMemoryContext(nullptr, image);
    require(unavailable.allocations.size() == 1 &&
            unavailable.moduleSnapshot.status == ModuleSnapshotStatus::Failed &&
            unavailable.allocations[0].moduleStatus == ModuleAssociationStatus::Unavailable &&
            unavailable.allocations[0].mappedFileStatus == MappedFileStatus::Unavailable,
            "Context failure discarded the observed allocation");
    require(collectMemoryContext(nullptr, {}).allocations.empty(), "Empty scan attempted context enrichment");
}


// ============================================================
// TEST PROGRAM ENTRY POINT
// ============================================================

int main()
{
    try
    {
        testGrouping();
        testModuleAssociation();
        testReporting();
        testLiveContext();
        std::cout << "All allocation context checks passed.\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        // Stack unwinding restores output and releases all fixture resources.
        std::cerr << "[FAIL] " << error.what() << '\n';
        return 1;
    }
}
