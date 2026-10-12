
#include "ProcessScanner.h"
#include "MemoryScanner.h"
#include "AuditMetrics.h"
#include "WindowsHandle.h"

#include <iostream>
#include <string>

/*
 * ProcessScanner.cpp
 *
 * Manages access to a target Windows process.
 *
 * Version 0.4 adds:
 *   - Scan completion tracking
 *   - Memory statistics
 *   - Region display filtering
 *   - Expanded audit summaries
 *
 * Version 0.4.1:
 *   - Releases handles if an exception interrupts scanning
 *   - Reports process handle cleanup failures
 *
 * Version 0.5:
 *   - Uses shared memory exposure classification
 *   - Reports investigation priorities instead of severity
 *   - Adds a filter for all prioritized regions
 */

void scanProcess(DWORD pid)
{
    // --------------------------------------------------------
    // STEP 1: OPEN TARGET PROCESS
    // --------------------------------------------------------

    std::cout << "\n[INFO] Opening process " << pid << "...\n";

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (process == nullptr) {
        DWORD errorCode = GetLastError();
        std::cerr << "[ERROR] Unable to open process.\n";
        std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';
        return;
    }

    // Keep ownership separate from the handle used by Windows APIs.
    WindowsHandle processHandle(process);

    std::cout << "[SUCCESS] Process opened successfully!\n";

    // --------------------------------------------------------
    // STEP 2: ENUMERATE MEMORY REGIONS
    // --------------------------------------------------------

    std::cout << "[INFO] Enumerating virtual memory...\n";

    ScanResult result = enumerateMemoryRegions(process);

    std::cout << "[INFO] Collected " << result.regions.size() << " committed regions.\n";

    // --------------------------------------------------------
    // STEP 3: CALCULATE MEMORY STATISTICS
    // --------------------------------------------------------

    /*
     * Calculate memory totals from all collected regions.
     *
     * These values are independent of the display filter.
     */
    MemoryStatistics statistics = calculateMemoryStatistics(result.regions);

    // --------------------------------------------------------
    // STEP 4: RECORD INVESTIGATION PRIORITIES
    // --------------------------------------------------------

    /*
     * Apply the same classification used by the region table.
     * Each region receives at most one investigation priority.
     * These counts do not establish external memory access
     * or confirm that an injection opportunity is exploitable.
     */
    AuditMetrics metrics = calculateAuditMetrics(result.regions);

    // --------------------------------------------------------
    // STEP 5: SELECT DISPLAY FILTER
    // --------------------------------------------------------

    std::cout << "\n================ DISPLAY FILTER ================\n\n";
    std::cout << "[1] All committed regions\n";
    std::cout << "[2] Executable regions only\n";
    std::cout << "[3] Ordinary W+X regions (excludes copy-on-write)\n";
    std::cout << "[4] Regions requiring investigation\n\n";
    std::cout << "Select display filter: ";

    std::string selection;

    /*
     * Read the entire line so inputs such as "2abc"
     * are not accidentally accepted as option 2.
     *
     * main.cpp already uses getline() for menu input,
     * so there should be no leftover newline to consume.
     */
    DisplayFilter filter = DisplayFilter::All;

    if (std::getline(std::cin, selection)) {
        if (selection == "2") {
            filter = DisplayFilter::Executable;
        }
        else if (selection == "3") {
            filter = DisplayFilter::WritableExecutable;
        }
        else if (selection == "4") {
            filter = DisplayFilter::Review;
        }
        else if (selection != "1") {
            std::cout
                << "[WARNING] Invalid filter. "
                << "Displaying all regions.\n";
        }
    }
    else {
        std::cout
            << "[WARNING] No filter selected. "
            << "Displaying all regions.\n";
    }

    // --------------------------------------------------------
    // STEP 6: DISPLAY SCAN RESULTS
    // --------------------------------------------------------

    displayMemoryRegions(result.regions, filter);

    displayAuditSummary(result, statistics, metrics);

    // --------------------------------------------------------
    // STEP 7: RELEASE PROCESS HANDLE
    // --------------------------------------------------------

    /*
     * Explicit cleanup allows us to report a Windows error.
     * The owner also releases the handle if an exception
     * interrupts scanning before this step is reached.
     *
     * This does not terminate the target process.
     */
    if (!processHandle.close())
    {
        DWORD errorCode = GetLastError();
        std::cerr << "[ERROR] Unable to close process handle.\n";
        std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';
        return;
    }

    std::cout << "\n[SUCCESS] Process handle closed.\n";
}
