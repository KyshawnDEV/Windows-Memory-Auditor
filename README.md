# Windows Memory Auditor v0.6

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
- `include/`: region metadata, scan results, exposure categories, statistics,
  priority counters, and Windows handle ownership.

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

The main menu retains process listing, scanning by PID, and exit. After a scan:

1. All committed regions.
2. Executable regions, including guarded and executable COW regions.
3. Ordinary W+X regions, excluding COW.
4. Regions with a high, medium, or low investigation priority.

The selected display filter does not change overall statistics or priorities.

## Access and scan limitations

The auditor requests only `PROCESS_QUERY_INFORMATION`. It does not read memory
contents, write memory, change protections, create threads, or suspend targets.
External write access is **not assessed**: region permissions do not determine
which other processes can obtain access rights to the target.

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
context, Unicode reporting, and live image/readonly file mappings. Both test
programs run through CTest. Live fixtures currently validate native x64 targets;
live WOW64 validation remains outstanding.

## Version history

- **v0.4.1:** stale comment updates, EOF handling, enumeration error reporting,
  exception-safe handle ownership, write-combine flag display, and CMake build task.
- **v0.5:** memory exposure categories, separate COW accounting, private executable
  analysis, investigation priorities, guarded base permissions, investigation
  filter, architecture reporting, and automated exposure tests.
- **v0.6:** original allocation bases, allocation context headers, loader module
  associations, mapped-file paths, explicit context availability, a more precise
  no-permission label, and automated context tests.

The next planned milestone is **v0.7: repeated-scan comparisons**. External
access assessment remains a separate future milestone.

Windows API references: [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex),
[memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
and [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
Context references: [MEMORY_BASIC_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information),
[module snapshots](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot),
and [GetMappedFileNameW](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmappedfilenamew).
