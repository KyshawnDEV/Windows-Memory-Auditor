#pragma once

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "MemoryExposure.h"
#include "ScanResult.h"

/*
 * ScanComparison.h
 *
 * Stores v0.7 memory observations and compares committed address ranges.
 * Matching PID and process creation time establish process identity.
 * Matching allocation metadata does not establish allocation identity:
 * memory can be released and recreated at the same address between scans.
 */
struct ScanSnapshot
{
    DWORD pid = 0;
    std::uint64_t processCreationTime = 0;
    bool identityKnown = false;
    DWORD identityErrorCode = ERROR_SUCCESS;

    // UTC wall-clock timestamps describe the memory walk, not later context lookup.
    FILETIME startedAt{};
    FILETIME completedAt{};

    // Duration uses a monotonic clock so wall-clock adjustments cannot make it negative.
    std::uint64_t elapsedMilliseconds = 0;
    ScanResult memory;
};

enum class ComparisonStatus
{
    Compared,
    IdentityUnavailable,
    DifferentProcess,
    FailedScan,
    InvalidRegionData
};

enum class RegionChangeKind
{
    Added,
    Removed,
    AttributesChanged,
    AllocationMetadataChanged,
    UnobservedInPrevious,
    UnobservedInCurrent
};

struct RegionChange
{
    // The affected interval may be only part of an original queried region.
    std::uintptr_t baseAddress = 0;
    std::uint64_t regionSize = 0;
    RegionChangeKind kind = RegionChangeKind::AttributesChanged;

    // An absent side means no committed range was observed there in that scan.
    std::optional<MemoryRegion> before;
    std::optional<MemoryRegion> after;
    bool protectionChanged = false;
    bool exposureChanged = false;
    bool priorityChanged = false;
};

struct ScanComparison
{
    ComparisonStatus status = ComparisonStatus::IdentityUnavailable;
    std::vector<RegionChange> changes;
};

/*
 * ScanHistory
 *
 * Retains the last complete, identity-verified scan for each PID.
 * Partial/failed scans cannot replace a complete baseline.
 * Eight targets are retained; updating a PID makes it most recent.
 * All history disappears when the auditor exits.
 */
class ScanHistory
{
public:
    static constexpr std::size_t MAX_BASELINES = 8;
    const ScanSnapshot* find(DWORD pid) const;
    bool remember(ScanSnapshot snapshot);

private:
    std::map<DWORD, ScanSnapshot> snapshots_;
    std::deque<DWORD> order_;
};

// Capture identity and timing without requesting additional process access rights.
ScanSnapshot captureMemorySnapshot(HANDLE process);

// Compare overlapping intervals rather than treating VirtualQueryEx row boundaries as identity.
ScanComparison compareMemorySnapshots(const ScanSnapshot& previous, const ScanSnapshot& current);

// Reporting is independent of the region display filter and does not claim observed causality.
std::string scanTimeToString(const FILETIME& time);
void displayScanTiming(const ScanSnapshot& snapshot);
void displayScanComparison(const ScanSnapshot& previous, const ScanSnapshot& current,
    const ScanComparison& comparison);
