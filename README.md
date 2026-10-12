# Windows Memory Auditor v0.5

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
- `include/`: region metadata, scan results, exposure categories, statistics,
  priority counters, and Windows handle ownership.

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

## Version history

- **v0.4.1:** stale comment updates, EOF handling, enumeration error reporting,
  exception-safe handle ownership, write-combine flag display, and CMake build task.
- **v0.5:** memory exposure categories, separate COW accounting, private executable
  analysis, investigation priorities, guarded base permissions, investigation
  filter, architecture reporting, and automated exposure tests.

Windows API references: [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex),
[memory protection constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants),
and [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).
