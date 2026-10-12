
#include "ProcessScanner.h"
#include "MemoryScanner.h"
#include "AuditMetrics.h"

#include <iostream>
#include <vector>

/*
 * ProcessScanner.cpp
 *
 * Manages access to the target Windows process.
 *
 * Responsibilities:
 *   - Open the target process
 *   - Verify process access
 *   - Invoke memory enumeration
 *   - Invoke memory analysis
 *   - Release the process handle
 *
 * Memory enumeration and analysis are implemented
 * separately in MemoryScanner.cpp.
 */

void scanProcess(DWORD pid)
{
    std::cout << "\n[INFO] Opening process "
              << pid << "...\n";

    // --------------------------------------------------------
    // STEP 1: OPEN THE TARGET PROCESS
    // --------------------------------------------------------

    /*
     * PROCESS_QUERY_INFORMATION:
     *   Allows querying the target's memory metadata.
     *
     * No process memory write permissions are requested.
     */
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    // --------------------------------------------------------
    // STEP 2: VERIFY PROCESS ACCESS
    // --------------------------------------------------------

    if (process == nullptr)
    {
        std::cerr << "[ERROR] Unable to open process.\n";
        std::cerr << "[ERROR] Windows error code: " << GetLastError() << '\n';
        return;
    }

    std::cout << "[SUCCESS] Process opened successfully!\n";

    // --------------------------------------------------------
    // STEP 3: INITIALIZE AUDIT METRICS
    // --------------------------------------------------------

    /*
     * Each scan gets its own counters.
     *
     * Results from previous scans are not carried over.
     */
    AuditMetrics metrics{};

    // --------------------------------------------------------
    // STEP 4: ENUMERATE MEMORY REGIONS
    // --------------------------------------------------------

    std::cout << "[INFO] Enumerating virtual memory...\n";

    /*
     * Collect committed virtual memory regions.
     */
    std::vector<MemoryRegion> regions = enumerateMemoryRegions(process);

    std::cout << "[INFO] Collected " << regions.size() << " committed regions.\n";

    // --------------------------------------------------------
    // STEP 5: ANALYZE MEMORY REGIONS
    // --------------------------------------------------------

    /*
     * Examine protection flags and update findings.
     */
    analyzeMemoryRegions(regions, metrics);

    // --------------------------------------------------------
    // STEP 6: RELEASE PROCESS HANDLE
    // --------------------------------------------------------

    /*
     * CloseHandle() releases our reference to the process.
     * It does not terminate the target application.
     */
    CloseHandle(process);

    std::cout << "\n[SUCCESS] Process handle closed.\n";
}
