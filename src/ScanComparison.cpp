#include "ScanComparison.h"
#include "MemoryScanner.h"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <utility>

// Baseline storage uses the same validation as the comparison path.
static bool orderedRegions(const ScanResult& scan, std::vector<const MemoryRegion*>& ordered);

/*
 * ScanComparison.cpp
 *
 * Compares sampled memory metadata, not memory contents or execution.
 * Differences describe what was observed in two address walks.
 * Changes that happen and disappear between walks cannot be detected.
 */

// ============================================================
// SNAPSHOT CAPTURE AND SESSION HISTORY
// ============================================================

ScanSnapshot captureMemorySnapshot(HANDLE process)
{
    ScanSnapshot snapshot{};
    GetSystemTimeAsFileTime(&snapshot.startedAt);
    auto started = std::chrono::steady_clock::now();

    if (process == nullptr || process == INVALID_HANDLE_VALUE)
    {
        snapshot.identityErrorCode = ERROR_INVALID_HANDLE;
    }
    else
    {
        snapshot.pid = GetProcessId(process);

        if (snapshot.pid == 0)
        {
            snapshot.identityErrorCode = GetLastError();
        }
        else
        {
            /*
             * A PID can be reused after a process exits. Creation time
             * distinguishes those process instances and can be queried
             * with the existing PROCESS_QUERY_INFORMATION handle.
             * Identity failure does not discard usable memory observations.
             */
            FILETIME creation{}, exit{}, kernel{}, user{};

            if (GetProcessTimes(process, &creation, &exit, &kernel, &user))
            {
                snapshot.processCreationTime =
                    (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
                snapshot.identityKnown = snapshot.processCreationTime != 0;
            }
            else
            {
                snapshot.identityErrorCode = GetLastError();
            }
        }
    }

    snapshot.memory = enumerateMemoryRegions(process);
    GetSystemTimeAsFileTime(&snapshot.completedAt);
    snapshot.elapsedMilliseconds = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    return snapshot;
}

const ScanSnapshot* ScanHistory::find(DWORD pid) const
{
    auto found = snapshots_.find(pid);
    return found == snapshots_.end() ? nullptr : &found->second;
}

bool ScanHistory::remember(ScanSnapshot snapshot)
{
    if (!snapshot.identityKnown || snapshot.pid == 0 || snapshot.processCreationTime == 0 ||
        snapshot.memory.status != ScanStatus::Complete)
        return false;

    std::vector<const MemoryRegion*> ordered;

    if (!orderedRegions(snapshot.memory, ordered))
        return false;

    DWORD pid = snapshot.pid;
    order_.erase(std::remove(order_.begin(), order_.end(), pid), order_.end());

    if (snapshots_.find(pid) == snapshots_.end() && snapshots_.size() >= MAX_BASELINES)
    {
        snapshots_.erase(order_.front());
        order_.pop_front();
    }

    snapshots_[pid] = std::move(snapshot);
    order_.push_back(pid);
    return true;
}


// ============================================================
// REGION VALIDATION AND COVERAGE
// ============================================================

/*
 * orderedRegions()
 *
 * Normalizes order without changing either snapshot. Reject invalid
 * sizes, overflowing endpoints, or overlapping committed records.
 * A comparison must not silently invent a result from ambiguous input.
 */
static bool orderedRegions(const ScanResult& scan, std::vector<const MemoryRegion*>& ordered)
{
    if (scan.maximumAddress != 0 && scan.minimumAddress > scan.maximumAddress)
        return false;

    for (const MemoryRegion& region : scan.regions)
    {
        if (region.state != MEM_COMMIT || region.regionSize == 0 ||
            region.regionSize > std::numeric_limits<std::uintptr_t>::max() - region.baseAddress)
            return false;

        if (scan.maximumAddress != 0 &&
            (region.baseAddress < scan.minimumAddress ||
             region.baseAddress + region.regionSize - 1 > scan.maximumAddress))
            return false;

        ordered.push_back(&region);
    }

    std::sort(ordered.begin(), ordered.end(), [](const MemoryRegion* left, const MemoryRegion* right)
        { return left->baseAddress < right->baseAddress; });

    for (std::size_t index = 1; index < ordered.size(); index++)
    {
        if (ordered[index]->baseAddress < ordered[index - 1]->baseAddress + ordered[index - 1]->regionSize)
            return false;
    }

    return true;
}

/*
 * coversAbsence()
 *
 * Absence is usable only inside the bounds of a complete address walk.
 * A missing range in partial or failed coverage is unobserved, not removed.
 * The same rule prevents claiming an addition against a partial baseline.
 */
static bool coversAbsence(const ScanResult& scan, std::uintptr_t begin, std::uintptr_t end)
{
    return scan.status == ScanStatus::Complete && scan.maximumAddress != 0 &&
           begin >= scan.minimumAddress && end - 1 <= scan.maximumAddress;
}

static bool sameAttributes(const std::optional<MemoryRegion>& left,
    const std::optional<MemoryRegion>& right)
{
    if (left.has_value() != right.has_value())
        return false;

    if (!left)
        return true;

    return left->protection == right->protection && left->type == right->type &&
           left->allocationBase == right->allocationBase &&
           left->allocationProtection == right->allocationProtection;
}


// ============================================================
// ADDRESS RANGE COMPARISON
// ============================================================

ScanComparison compareMemorySnapshots(const ScanSnapshot& previous, const ScanSnapshot& current)
{
    ScanComparison comparison{};

    if (!previous.identityKnown || !current.identityKnown || previous.pid == 0 || current.pid == 0 ||
        previous.processCreationTime == 0 || current.processCreationTime == 0)
        return comparison;

    if (previous.pid != current.pid || previous.processCreationTime != current.processCreationTime)
    {
        comparison.status = ComparisonStatus::DifferentProcess;
        return comparison;
    }

    if (previous.memory.status == ScanStatus::Failed || current.memory.status == ScanStatus::Failed)
    {
        comparison.status = ComparisonStatus::FailedScan;
        return comparison;
    }

    std::vector<const MemoryRegion*> oldRegions;
    std::vector<const MemoryRegion*> newRegions;

    if (!orderedRegions(previous.memory, oldRegions) || !orderedRegions(current.memory, newRegions))
    {
        comparison.status = ComparisonStatus::InvalidRegionData;
        return comparison;
    }

    /*
     * Partition at every start/end boundary observed in either scan.
     * Each interval has at most one old and one new committed record.
     * A protection-induced split or merge therefore compares the same
     * addresses instead of appearing as whole-row removal and addition.
     */
    std::vector<std::uintptr_t> boundaries;

    for (const auto& ordered : {oldRegions, newRegions})
    {
        for (const MemoryRegion* region : ordered)
        {
            boundaries.push_back(region->baseAddress);
            boundaries.push_back(region->baseAddress + region->regionSize);
        }
    }

    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());
    std::size_t oldIndex = 0;
    std::size_t newIndex = 0;
    comparison.status = ComparisonStatus::Compared;

    for (std::size_t index = 0; index + 1 < boundaries.size(); index++)
    {
        std::uintptr_t begin = boundaries[index];
        std::uintptr_t end = boundaries[index + 1];

        while (oldIndex < oldRegions.size() &&
               oldRegions[oldIndex]->baseAddress + oldRegions[oldIndex]->regionSize <= begin)
            oldIndex++;

        while (newIndex < newRegions.size() &&
               newRegions[newIndex]->baseAddress + newRegions[newIndex]->regionSize <= begin)
            newIndex++;

        const MemoryRegion* before = oldIndex < oldRegions.size() && oldRegions[oldIndex]->baseAddress <= begin
            ? oldRegions[oldIndex] : nullptr;
        const MemoryRegion* after = newIndex < newRegions.size() && newRegions[newIndex]->baseAddress <= begin
            ? newRegions[newIndex] : nullptr;

        if (before == nullptr && after == nullptr)
            continue;

        RegionChange change{};
        change.baseAddress = begin;
        change.regionSize = end - begin;

        if (before != nullptr)
            change.before = *before;

        if (after != nullptr)
            change.after = *after;

        if (before == nullptr)
        {
            change.kind = coversAbsence(previous.memory, begin, end)
                ? RegionChangeKind::Added : RegionChangeKind::UnobservedInPrevious;
        }
        else if (after == nullptr)
        {
            change.kind = coversAbsence(current.memory, begin, end)
                ? RegionChangeKind::Removed : RegionChangeKind::UnobservedInCurrent;
        }
        else
        {
            MemoryExposure oldExposure = classifyMemoryExposure(*before);
            MemoryExposure newExposure = classifyMemoryExposure(*after);
            change.protectionChanged = before->protection != after->protection;
            change.exposureChanged = oldExposure.category != newExposure.category;
            change.priorityChanged = oldExposure.priority != newExposure.priority;

            bool allocationChanged = before->allocationBase != after->allocationBase ||
                before->allocationProtection != after->allocationProtection || before->type != after->type;

            if (!allocationChanged && !change.protectionChanged && !change.exposureChanged && !change.priorityChanged)
                continue;

            change.kind = allocationChanged
                ? RegionChangeKind::AllocationMetadataChanged : RegionChangeKind::AttributesChanged;
        }

        /*
         * Merge adjacent intervals with identical observed attributes.
         * Row boundaries alone must not inflate the change count.
         * Each remaining record represents one changed address range,
         * not one OS event or one confirmed allocation lifetime.
         */
        if (!comparison.changes.empty())
        {
            RegionChange& last = comparison.changes.back();

            if (last.baseAddress + last.regionSize == change.baseAddress && last.kind == change.kind &&
                sameAttributes(last.before, change.before) && sameAttributes(last.after, change.after))
            {
                last.regionSize += change.regionSize;
                continue;
            }
        }

        comparison.changes.push_back(change);
    }

    return comparison;
}


// ============================================================
// TIMING AND COMPARISON REPORTING
// ============================================================

std::string scanTimeToString(const FILETIME& time)
{
    SYSTEMTIME converted{};

    if ((time.dwLowDateTime == 0 && time.dwHighDateTime == 0) || !FileTimeToSystemTime(&time, &converted))
        return "Unavailable";

    std::ostringstream output;
    output << std::setfill('0') << std::setw(4) << converted.wYear << '-'
           << std::setw(2) << converted.wMonth << '-' << std::setw(2) << converted.wDay << ' '
           << std::setw(2) << converted.wHour << ':' << std::setw(2) << converted.wMinute << ':'
           << std::setw(2) << converted.wSecond << '.' << std::setw(3) << converted.wMilliseconds << " UTC";
    return output.str();
}

void displayScanTiming(const ScanSnapshot& snapshot)
{
    std::cout << "\nMemory scan started: " << scanTimeToString(snapshot.startedAt) << '\n';
    std::cout << "Memory scan finished: " << scanTimeToString(snapshot.completedAt) << '\n';
    std::cout << "Memory scan duration: " << snapshot.elapsedMilliseconds << " ms\n";
    std::cout << "Process identity: " << (snapshot.identityKnown ? "PID + creation time verified" : "Unavailable");

    if (!snapshot.identityKnown && snapshot.identityErrorCode != ERROR_SUCCESS)
        std::cout << " (Windows error: " << snapshot.identityErrorCode << ')';

    std::cout << '\n';
}

void displayScanComparison(const ScanSnapshot& previous, const ScanSnapshot& current,
    const ScanComparison& comparison)
{
    std::cout << "\n---------------- REPEATED-SCAN COMPARISON ----------------\n";
    std::cout << "Previous scan: " << scanTimeToString(previous.startedAt) << '\n';
    std::cout << "Current scan: " << scanTimeToString(current.startedAt) << '\n';

    auto statusLabel = [](ScanStatus status)
    {
        switch (status)
        {
            case ScanStatus::Complete: return "COMPLETE";
            case ScanStatus::Partial: return "PARTIAL";
            case ScanStatus::Failed: return "FAILED";
        }

        return "UNKNOWN";
    };
    std::cout << "Previous / current coverage: " << statusLabel(previous.memory.status)
              << " / " << statusLabel(current.memory.status) << '\n';

    if (comparison.status != ComparisonStatus::Compared)
    {
        switch (comparison.status)
        {
            case ComparisonStatus::IdentityUnavailable:
                std::cout << "[WARNING] Comparison skipped: process identity could not be verified.\n";
                break;
            case ComparisonStatus::DifferentProcess:
                std::cout << "[INFO] Comparison skipped: different process instance (PID or creation time differs).\n";
                break;
            case ComparisonStatus::FailedScan:
                std::cout << "[WARNING] Comparison skipped: a memory scan failed.\n";
                break;
            case ComparisonStatus::InvalidRegionData:
                std::cout << "[WARNING] Comparison skipped: invalid or overlapping region data.\n";
                break;
            case ComparisonStatus::Compared:
                break;
        }

        return;
    }

    std::size_t added = 0, removed = 0, attributes = 0, allocationMetadata = 0;
    std::size_t unobservedPrevious = 0, unobservedCurrent = 0;
    std::size_t protections = 0, exposures = 0, priorities = 0;

    for (const RegionChange& change : comparison.changes)
    {
        switch (change.kind)
        {
            case RegionChangeKind::Added: added++; break;
            case RegionChangeKind::Removed: removed++; break;
            case RegionChangeKind::AttributesChanged: attributes++; break;
            case RegionChangeKind::AllocationMetadataChanged: allocationMetadata++; break;
            case RegionChangeKind::UnobservedInPrevious: unobservedPrevious++; break;
            case RegionChangeKind::UnobservedInCurrent: unobservedCurrent++; break;
        }

        protections += change.protectionChanged;
        exposures += change.exposureChanged;
        priorities += change.priorityChanged;
    }

    std::cout << "Added committed ranges: " << added << '\n';
    std::cout << "Removed committed ranges: " << removed << '\n';
    std::cout << "Ranges with changed attributes: " << attributes << '\n';
    std::cout << "Ranges with changed allocation metadata: " << allocationMetadata << '\n';
    std::cout << "Protection / exposure / priority differences: "
              << protections << " / " << exposures << " / " << priorities << '\n';
    std::cout << "Unobserved in previous / current coverage: "
              << unobservedPrevious << " / " << unobservedCurrent << '\n';

    for (const RegionChange& change : comparison.changes)
    {
        std::cout << "\n0x" << std::hex << std::uppercase << change.baseAddress << std::dec
                  << " | Bytes: " << change.regionSize << " | ";

        switch (change.kind)
        {
            case RegionChangeKind::Added: std::cout << "Added committed range"; break;
            case RegionChangeKind::Removed: std::cout << "Removed committed range"; break;
            case RegionChangeKind::AttributesChanged: std::cout << "Observed attribute difference"; break;
            case RegionChangeKind::AllocationMetadataChanged:
                std::cout << "Allocation metadata differs; continuity unknown";
                break;
            case RegionChangeKind::UnobservedInPrevious: std::cout << "Unobserved in previous coverage"; break;
            case RegionChangeKind::UnobservedInCurrent: std::cout << "Unobserved in current coverage"; break;
        }

        std::cout << '\n';

        const std::pair<const char*, const std::optional<MemoryRegion>*> sides[] =
        {
            {"Before", &change.before},
            {"After", &change.after}
        };

        for (const auto& side : sides)
        {
            if (!*side.second)
                continue;

            const MemoryRegion& region = **side.second;
            MemoryExposure exposure = classifyMemoryExposure(region);
            std::cout << "  " << side.first << ": " << protectionToString(region.protection)
                      << " (raw 0x" << std::hex << std::uppercase << region.protection << std::dec << ')'
                      << " | " << memoryTypeToString(region.type) << " | ["
                      << priorityToString(exposure.priority) << "] " << exposureToString(exposure.category)
                      << " | Allocation base: ";

            if (region.allocationBase == 0)
                std::cout << "Unavailable";
            else
                std::cout << "0x" << std::hex << std::uppercase << region.allocationBase << std::dec;

            std::cout << " | Allocation protection: " << protectionToString(region.allocationProtection)
                      << " (raw 0x" << std::hex << std::uppercase << region.allocationProtection << std::dec << ')';
            std::cout << '\n';
        }
    }

    if (comparison.changes.empty())
        std::cout << "[INFO] No sampled memory metadata differences observed.\n";

    std::cout << "[INFO] Comparisons use all collected regions, independent of the display filter.\n";
    std::cout << "[INFO] Differences were observed between scans; intermediate changes and causality are unknown.\n";
    std::cout << "[INFO] Matching addresses and allocation metadata do not prove allocation continuity.\n";
    std::cout << "[INFO] Removed ranges are no longer observed committed; this does not prove the allocation was released.\n";
    std::cout << "[INFO] Unobserved ranges are not classified as additions or removals.\n";
}
