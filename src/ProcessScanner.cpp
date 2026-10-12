
#include "ProcessScanner.h"
#include "MemoryScanner.h"
#include "AuditMetrics.h"

#include <iostream>
#include <limits>
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
 * Process handles are released after each scan.
 */

void scanProcess(DWORD pid)
{
    // --------------------------------------------------------
    // STEP 1: OPEN TARGET PROCESS
    // --------------------------------------------------------

    std::cout << "\n[INFO] Opening process " << pid << "...\n";

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (process == nullptr) {
        std::cerr << "[ERROR] Unable to open process.\n";
        std::cerr << "[ERROR] Windows error code: " << GetLastError() << '\n';
        return;
    }

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
    // STEP 4: RECORD SECURITY FINDINGS
    // --------------------------------------------------------

    AuditMetrics metrics{};

    /*
     * Each W+X region is currently classified as one
     * medium-severity indicator requiring investigation.
     *
     * Clamp to int's maximum because AuditMetrics
     * currently uses int counters.
     */
    if (statistics.suspiciousRegions > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        metrics.medium = std::numeric_limits<int>::max();
    }
    else {
        metrics.medium = static_cast<int>(statistics.suspiciousRegions);
    }

    // --------------------------------------------------------
    // STEP 5: SELECT DISPLAY FILTER
    // --------------------------------------------------------

    std::cout << "\n================ DISPLAY FILTER ================\n\n";
    std::cout << "[1] All committed regions\n";
    std::cout << "[2] Executable regions only\n";
    std::cout << "[3] W+X regions requiring review\n\n";
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
            filter = DisplayFilter::Suspicious;
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
     * CloseHandle() releases the process handle.
     *
     * This does not terminate the target process.
     */
    CloseHandle(process);

    std::cout << "\n[SUCCESS] Process handle closed.\n";
}
