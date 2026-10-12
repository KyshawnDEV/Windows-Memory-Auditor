# Windows Memory Auditor v0.8

Author: KyshawnDEV

A C++17 Windows console application for inspecting committed process memory
and prioritizing memory configurations for investigation. It evaluates potential
code storage and execution exposure. It is not an antivirus or malware classifier.

## Architecture

- `main.cpp`: validated console input and program control.
- `Menu.cpp`: main menu presentation.
- `ProcessEnumerator.cpp`: Tool Help process snapshots and process listing.
- `ProcessScanner.cpp`: query-only process access, scan orchestration, filters,
  and resource ownership.
- `MemoryScanner.cpp`: virtual memory queries, shared exposure classification,
  statistics, investigation priorities, and reports.
- `MemoryContext.cpp`: allocation grouping, Tool Help module snapshots,
  mapped-file paths, and context reporting.
- `ScanComparison.cpp`: timed snapshots, process identity verification,
  conservative address-range comparisons, and bounded session history.
- `AccessAssessment.cpp`: optional current-caller fresh-handle access probes,
  caller security metadata, granted-mask inspection, and scope reporting.
- `include/`: region metadata, scan results, exposure categories, statistics,
  priority counters, and Windows handle ownership.

## Current-caller access assessment

v0.8 adds main-menu option **3: Assess current-caller process access by PID**.
It is independent of scanning, filters, exposure priorities, and scan history.
Option 2 continues to open only a query handle for metadata scanning.
Option 3 obtains separate capability-bearing handles and closes them without
reading/writing target memory, changing protections, or creating target threads.

The assessment records UTC start/end times and the effective caller context:
process or thread impersonation token, user SID, integrity RID, elevation,
restricted SIDs, AppContainer state/package SID, enabled privileges, and the
observed state of `SeDebugPrivilege`. It reads tokens only with `TOKEN_QUERY`.
It does not enable or disable privileges, elevate, or impersonate another caller.
Unavailable metadata stays explicitly unavailable instead of becoming a default.

Eight independent fresh-handle profiles are tested:

| Profile | Capability rights requested |
|---|---|
| Limited query | `PROCESS_QUERY_LIMITED_INFORMATION` |
| Memory query | `PROCESS_QUERY_INFORMATION` |
| Read-related | `PROCESS_VM_READ` |
| Write-related | `PROCESS_VM_WRITE` |
| Memory operations | `PROCESS_VM_OPERATION` |
| Write + operations | `PROCESS_VM_WRITE \| PROCESS_VM_OPERATION` |
| Thread creation | `PROCESS_CREATE_THREAD` |
| Write + operations + thread | `PROCESS_VM_WRITE \| PROCESS_VM_OPERATION \| PROCESS_CREATE_THREAD` |

Every profile additionally includes `PROCESS_QUERY_LIMITED_INFORMATION` for
PID/creation-time verification on the returned handle. Reports show the exact
requested mask. Denial applies to that combined request, not proof that one
isolated capability is denied. A separate retained anchor requests limited
query plus `SYNCHRONIZE` for identity and zero-time process-exit checks. If
the anchor cannot be obtained, capability profiles remain **not attempted**.

Returned handles are inspected with dynamically resolved `NtQueryObject()`
`ObjectBasicInformation`. The reported granted mask must contain all requested
bits before a profile is labeled **requested handle rights verified**. This
accounts for object callbacks that can reduce access on a successful open.
If fewer rights are present, the report says so. If native mask inspection is
unavailable, it reports only that a handle was returned and leaves grants
unknown. Native NTSTATUS errors are labeled separately from Win32 errors.

Caller token identity/security-modification identifiers are checked before and
after each probe. Changed or unverifiable caller contexts stop further probes.
PID and process creation time are checked against the anchor; mismatches and
process exits also stop assessment. Checks are sampled observations, not an
atomic lock on the caller or target. Probe handles are closed immediately,
with cleanup failures reported separately. `PROCESS_ALL_ACCESS` is not requested.

**Complete** means all profiles were attempted, not that all were granted.
`ERROR_ACCESS_DENIED` is reported as request denial; invalid PIDs and other API
failures remain distinct failures. The assessment does not diagnose whether
a denial came from an ACL, integrity policy, AppContainer restrictions,
protected-process restrictions, or another enforcement mechanism.

Results apply only to this caller's fresh opens at the recorded time. Existing,
inherited, or duplicated handles and other callers are not enumerated. A
verified write-related handle mask does not prove that a particular region
can be modified or that an execution/injection path would succeed. The
assessment does not attempt `WriteProcessMemory`, `VirtualProtectEx`, or
`CreateRemoteThread`, and does not change memory-exposure priorities.

## Repeated-scan comparisons

v0.7 uses the existing scan-by-PID option. The first complete, identity-verified
scan becomes that PID's baseline. Scanning it again displays a comparison
against the most recent complete baseline, then replaces that baseline only
if the new scan is complete and its identity is verified. There is no background
polling or automatic rescan; repeat the menu operation when another sample is wanted.

History remains in memory for this console session and retains up to eight
targets, evicting the least recently updated baseline when necessary. It is
not saved to disk. Partial and failed scans never replace a complete baseline.
Comparisons use all collected regions regardless of the selected display filter.

Each memory walk records UTC start/end times and a duration from a monotonic
clock. Process identity uses PID plus the creation time obtained from
`GetProcessTimes()` on the opened query-only handle. A reused PID with a
different creation time is not compared to the previous process instance.
If identity cannot be verified, memory reporting still works but comparison
and baseline storage are skipped.

Comparisons report added/removed committed address ranges, current protection
differences, exposure-category differences, priority differences, and changes
in allocation metadata. Overlapping intervals are compared instead of matching
whole `VirtualQueryEx()` rows: a protection-induced split or merge does not
create false additions/removals. Adjacent intervals with identical differences
are combined; counts represent sampled address ranges, not OS events.

Missing committed ranges count as added or removed only when the opposite scan
has complete coverage of those addresses. Otherwise they are explicitly
unobserved. A partial current scan can still show positive observations and
attribute differences against a complete baseline, but cannot establish removals.
Failed scans are not compared. Invalid, overlapping, or overflowing region
records are rejected rather than producing ambiguous comparisons.

Matching addresses, allocation bases, types, and allocation protections do
not prove allocation continuity. Memory may be released and recreated with
identical metadata between samples. Differences in allocation metadata are
reported separately; no allocation lifetime, injection event, or causality is
inferred. "Removed committed range" can mean decommitment rather than release
of the reservation. Intermediate changes, content-only changes, and brief
write/execute windows between scans are not detected.

## Allocation and module context

v0.6 preserves `MEMORY_BASIC_INFORMATION::AllocationBase` alongside each
region's `BaseAddress`. The allocation base identifies the original allocation
or mapped view; the region base identifies a queried range with uniform
attributes. Several protection ranges can therefore belong to one allocation.

Region rows keep their existing order and filters. Each displayed allocation
gets a context header with the original base, observed committed byte and
region totals, executable/W+X region counts, and highest observed region
priority. Reserved gaps are not included in committed totals. Missing bases
are reported explicitly and those regions remain separate.

Tool Help module snapshots associate image allocations with observed loader
modules only when the allocation base and all collected image ranges fit the
module's recorded range. Private executable allocations are not assigned a
module simply because an address overlaps a module range. An association does
not lower exposure priorities or establish trustworthy contents.

`GetMappedFileNameW()` queries backing-file metadata for image and mapped
allocations using the existing query-only handle. Returned device paths are
retained without guessing a drive letter. Unicode strings are stored intact;
non-ASCII UTF-16 units and control characters are displayed as `\uXXXX` escapes
to preserve spelling in the existing console interface. Tool Help module paths
that may fill its fixed-size buffer are labeled as potentially truncated.

Context can be available, unavailable, not queried, or not applicable. A
complete module snapshot with no matching module is reported as "No matching
module observed," not as malicious memory. Paging-file-backed views may have
no filename. Context errors retain their Windows error codes when provided
and do not alter memory scan completion or hide collected regions.

Memory and context are separate observations, not an atomic snapshot. Context
summaries cover all collected allocation groups regardless of the display filter.

## Memory exposure analysis

Classification uses the current `MEMORY_BASIC_INFORMATION::Protect` value and
the region type reported by `VirtualQueryEx()`. `AllocationProtect` records the
original allocation protection and does not determine current permissions.

| Configuration | Investigation priority |
|---|---|
| Private memory with ordinary write and execute permissions | High |
| Private executable memory without ordinary write permission | Medium |
| Image, mapped, or unknown-type memory with ordinary W+X permissions | Medium |
| Executable copy-on-write memory | Low |
| Executable memory of unknown type, or unknown base protection | Low |
| Image/mapped executable memory without write/COW permission | Informational |
| Non-executable ordinary writable or copy-on-write memory | Informational |

Each region receives at most one investigation priority. Private executable
regions can have legitimate uses, including JIT compilation. Priorities guide
review and do not establish vulnerability severity or malicious intent.

`PAGE_READWRITE` and `PAGE_EXECUTE_READWRITE` contribute to ordinary writable
totals. `PAGE_WRITECOPY` and `PAGE_EXECUTE_WRITECOPY` contribute to separate
copy-on-write totals. A COW write creates a private copy for the writing process
rather than modifying the original shared backing through that mapping.

`PAGE_GUARD` remains visible and does not erase the underlying write/execute
classification. Guarded regions are not claimed to be immediately accessible.
Executable, writable, guarded, and type totals overlap; private W+X is a subset
of private executable memory. Byte totals describe committed virtual address
ranges, not resident physical RAM or the process's private commit charge.

## Console filters

The main menu offers process listing, scanning by PID, optional current-caller
access assessment by PID, and exit. After a memory scan:

1. All committed regions.
2. Executable regions, including guarded and executable COW regions.
3. Ordinary W+X regions, excluding COW.
4. Regions with a high, medium, or low investigation priority.

The selected display filter does not change overall statistics or priorities.

## Access and scan limitations

Memory scanning requests only `PROCESS_QUERY_INFORMATION`. It does not read memory
contents, write memory, change protections, create threads, or suspend targets.
External write access is **not assessed by the memory scan**: region permissions
do not determine which other processes can obtain access rights to the target.
The optional v0.8 operation separately assesses this caller's fresh handle
requests; it does not establish arbitrary external callers' access or region-level writability.

`MEM_PRIVATE` is a region type, not a complete inventory of physically private
pages. Modified COW pages can still be reported as `MEM_IMAGE` or `MEM_MAPPED`.
The auditor does not inspect page-level sharing, code contents, signatures,
control-flow mitigations, or process security descriptors.
Loader associations do not include every possible image mapping; module
snapshots can omit data-file loads and can fail while the loader list changes.
The auditor retries `ERROR_BAD_LENGTH` up to three times before reporting
unavailable module context. It does not identify the creator of a private
allocation or assign it a JIT/runtime origin without supporting evidence.

A 64-bit Windows toolchain is required. WOW64 target scans are capped at the
32-bit address ceiling. If a target rejects queries below that ceiling, the
scan remains partial rather than assuming an error means successful completion.
Targets can change memory during enumeration; a complete address walk is not
an atomic snapshot. Failed and partial scans retain explicit status and errors.

## Build and test

For an MSYS2 UCRT64 MinGW-w64 installation at `C:/msys64/ucrt64`:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_CXX_COMPILER=C:/msys64/ucrt64/bin/g++.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/ucrt64/bin/mingw32-make.exe
cmake --build build
ctest --test-dir build --output-on-failure
.\build\MemoryAuditor.exe
```

The VS Code default build task builds the configured `build` directory.
`BUILD_TESTING=OFF` disables test targets. `ExposureTests` checks classification,
statistics, filters, reporting, and query-only enumeration of controlled private,
guarded, mapped COW, executable COW, and image regions. Test allocations never
execute code. `MemoryTest` remains an interactive private RWX target for manual
auditor testing.

`ContextTests` checks grouping across protection changes and reserved gaps,
missing bases, module range validation, unchanged priorities, unavailable
context, Unicode reporting, and live image/readonly file mappings. These test
programs run through CTest. Live fixtures currently validate native x64 targets;
live WOW64 validation remains outstanding.

`ComparisonTests` checks process identity/PID reuse, interval splits/merges,
coverage boundaries, incomplete scans, baseline retention/eviction, timestamps,
report wording, and controlled live protection/commitment/decommitment changes.
These fixture mutations occur inside the test process; scanner snapshots
still use only `PROCESS_QUERY_INFORMATION`.

`AccessAssessmentTests` checks exact masks, open-error meanings, granted-mask
subset logic, effective process/thread tokens, unchanged caller fingerprints,
handle cleanup, and owned normal/restricted/exited child processes. The
restricted child grants query/read/synchronize to the caller's package when
running in an AppContainer, while retaining write/operation/thread denials.
An already enabled `SeDebugPrivilege` can bypass that fixture DACL; the test
reports this and omits that live denial expectation without changing privileges.
The child deliberately exits with code 259 to check synchronization-based exit
detection. Synthetic reports cover changed callers and unknown granted masks.
All four test programs run through CTest. Real protected-process/PPL policy
combinations are not exhaustively validated by these controlled fixtures.

## Version history

- **v0.4.1:** stale comment updates, EOF handling, enumeration error reporting,
  exception-safe handle ownership, write-combine flag display, and CMake build task.
- **v0.5:** memory exposure categories, separate COW accounting, private executable
  analysis, investigation priorities, guarded base permissions, investigation
  filter, architecture reporting, and automated exposure tests.
- **v0.6:** original allocation bases, allocation context headers, loader module
  associations, mapped-file paths, explicit context availability, a more precise
  no-permission label, and automated context tests.
- **v0.7:** timed snapshots, creation-time process identity, repeated comparisons
  against complete session baselines, interval-based differences, conservative
  partial coverage handling, and automated comparison tests.
- **v0.8:** optional current-caller access assessment, exact fresh-handle profiles,
  effective token metadata, granted-mask inspection, conservative verification,
  and automated access assessment tests.

Broader assessment for other callers and existing handles remains future work.

Windows API references: [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex),
[memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
and [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
Context references: [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information),
[module snapshots](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot),
and [GetMappedFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew).
Comparison identity reference: [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes).
Access assessment references: [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess),
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation),
[NtQueryObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject),
and [object callback access reduction](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_ob_pre_create_handle_information).
