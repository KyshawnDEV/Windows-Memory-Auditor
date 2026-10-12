
#include "Menu.h"
#include "ProcessEnumerator.h"
#include "ProcessScanner.h"
#include "ScanComparison.h"
#include "AccessAssessment.h"

#include <windows.h>
#include <iostream>
#include <string>
#include <limits>

/*
 * Windows Memory Auditor v0.8
 * Author: KyshawnDEV
 *
 * Purpose:
 *   Inspect Windows process memory permissions and types
 *   to identify configurations requiring investigation.
 *
 *   Memory permissions alone do not establish whether
 *   another process can access or modify a region.
 *
 * Current Features:
 *   - Interactive menu
 *   - Process enumeration
 *   - Process selection by PID
 *   - Input validation
 *   - Process handle management
 *   - Committed virtual memory enumeration
 *   - Memory type and protection analysis
 *   - W+X findings requiring review
 *   - Separate ordinary write and copy-on-write accounting
 *   - Executable region exposure and investigation priorities
 *   - Allocation grouping and observed module/file context
 *   - Timed snapshots and repeated-scan comparisons
 *   - Optional current-caller process access assessment
 *   - Committed memory statistics
 *   - Memory region display filters
 *   - Complete, partial, and failed scan reporting
 *
 * Scanning Behavior:
 *   Queries memory metadata without reading or modifying
 *   the target process's memory contents.
 *   Access assessment obtains separate capability-bearing
 *   handles, verifies identity, and closes them without use.
 *
 * Platform:
 *   Windows x86-64
 *
 * Compiler:
 *   MinGW-w64 / GCC
 */


// ============================================================
// INPUT VALIDATION
// ============================================================

/*
 * readUnsignedInteger()
 *
 * Reads an entire line from the console and verifies
 * that it contains only decimal digits.
 *
 * Parameters:
 *   value - Receives the validated integer.
 *   maxValue - Maximum accepted value.
 *
 * Returns:
 *   true  - Input is valid.
 *   false - Input is invalid or could not be read.
 *
 * Rejects:
 *   - Negative numbers
 *   - Letters
 *   - Decimal points
 *   - Empty input
 *   - Numbers exceeding the specified maximum
 */
bool readUnsignedInteger(unsigned long long& value, unsigned long long maxValue)
{
    std::string input;

    if (!std::getline(std::cin, input))
        return false;

    if (input.empty())
        return false;

    unsigned long long result = 0;

    for (char character : input)
    {
        // Reject anything that is not a decimal digit.
        if (character < '0' || character > '9')
            return false;

        unsigned int digit = character - '0';

        /*
         * Check for overflow before multiplying by 10.
         *
         * We want:
         *   result * 10 + digit <= maxValue
         *
         * Rearranging avoids overflowing the integer:
         *   result <= (maxValue - digit) / 10
         */
        if (digit > maxValue ||
            result > (maxValue - digit) / 10)
        {
            return false;
        }

        result = result * 10 + digit;
    }

    value = result;
    return true;
}


// ============================================================
// MAIN FUNCTION
// ============================================================

int main()
{
    bool running = true;

    /*
     * Retain complete baselines for this console session only.
     * Scanning a PID again compares against its saved baseline;
     * no extra menu or background polling is required.
     */
    ScanHistory history;

    while (running)
    {
        displayMenu();

        unsigned long long selection = 0;

        // Read and validate the menu selection.
        if (!readUnsignedInteger(selection, 3))
        {
            /*
             * A closed or failed input stream cannot provide
             * another selection. Exit before retrying so EOF
             * does not cause an endless menu and error loop.
             */
            if (!std::cin)
                break;

            std::cout << "\n[ERROR] Invalid menu selection.\n";
            continue;
        }

        switch (selection)
        {
            // ------------------------------------------------
            // OPTION 1: LIST RUNNING PROCESSES
            // ------------------------------------------------
            case 1:
            {
                std::vector<ProcessInfo> processes =
                    enumerateProcesses();

                displayProcesses(processes);
                break;
            }

            // ------------------------------------------------
            // OPTION 2: SCAN PROCESS BY PID
            // ------------------------------------------------
            case 2:
            {
                unsigned long long inputPid = 0;

                std::cout << "\nEnter target Process ID (PID): ";

                if (!readUnsignedInteger(
                        inputPid,
                        std::numeric_limits<DWORD>::max()) ||
                    inputPid == 0)
                {
                    std::cout << "[ERROR] Invalid PID.\n";
                    break;
                }

                DWORD pid = static_cast<DWORD>(inputPid);

                scanProcess(pid, history);
                break;
            }

            // ------------------------------------------------
            // OPTION 3: ASSESS CURRENT-CALLER PROCESS ACCESS
            // ------------------------------------------------
            case 3:
            {
                unsigned long long inputPid = 0;
                std::cout << "\nEnter target PID for current-caller access assessment: ";

                if (!readUnsignedInteger(inputPid, std::numeric_limits<DWORD>::max()) || inputPid == 0)
                {
                    std::cout << "[ERROR] Invalid PID.\n";
                    break;
                }

                /*
                 * Keep this optional operation separate from memory scanning.
                 * It requests process rights but never exercises them, and
                 * cannot replace a memory baseline or change its priorities.
                 */
                AccessAssessment assessment = assessProcessAccess(static_cast<DWORD>(inputPid));
                displayAccessAssessment(assessment);
                break;
            }

            // ------------------------------------------------
            // OPTION 0: EXIT
            // ------------------------------------------------
            case 0:
            {
                std::cout << "\n[INFO] Exiting MemoryAuditor...\n";
                running = false;
                break;
            }
        }

        // Stop if standard input has been closed.
        if (!std::cin)
            running = false;
    }

    return 0;
}
