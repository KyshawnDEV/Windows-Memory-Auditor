#include <iostream>
#include <windows.h>
#include <limits>

/*
 * Windows Memory Auditor v0.1
 * Author: KyshawnDEV
 *
 * Purpose:
 *   Inspect the virtual memory of Windows processes to
 *   identify potentially unsafe memory configurations.
 *
 * Current Features:
 *   - Accept a target process ID (PID)
 *   - Open a handle to the target process
 *   - Check whether the process can be accessed
 *   - Close the process handle when finished
 *
 * Future Features:
 *   - Enumerate virtual memory regions
 *   - Identify memory protection permissions
 *   - Detect writable and executable memory regions
 *   - Generate vulnerability assessment reports
 *
 * Platform:
 *   Windows x86-64
 *
 * Compiler:
 *   MinGW-w64 / GCC
 */

//Audit Metrics

/*
 * Stores the number of findings discovered during an audit.
 *
 * Each finding will eventually receive a severity rating.
 *
 * Critical:
 *   Reserved for confirmed, severe security vulnerabilities.
 *
 * High:
 *   Potentially dangerous memory configurations.
 *
 * Medium:
 *   Suspicious memory configurations requiring investigation.
 *
 * Low:
 *   Informational findings or minor security concerns.
 *
 * All counters start at zero.
 */
struct AuditMetrics {
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
};

//Display Menu
/*
 * Displays the main menu for the Windows Memory Auditor.
 *
 * Current Menu options:
 *   [1] Scan a process
 *   [0] Exit
 */
void displayMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       WINDOWS MEMORY AUDITOR v0.1\n";
    std::cout << "========================================\n\n";

    std::cout << "[1] Scan a process\n";
    std::cout << "[0] Exit\n\n";

    std::cout << "Make your menu selection now: ";
}

//main is main
int main()
{
    int selection = -1;

    // Keep displaying the menu until the user selects 0.
    while (selection != 0)
    {
        displayMenu();

        /*
         * Read the user's menu selection.
         *
         * std::cin.fail() detects invalid input such
         * as entering letters instead of an integer.
         */
        if (!(std::cin >> selection))
        {
            // Clear the input stream's error state.
            std::cin.clear();

            // Discard invalid input.
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(),'\n');

            std::cout << "\n[ERROR] Invalid selection.\n";
            continue;
        }

        switch (selection)
        {
            case 1:
            {
                unsigned long long inputPid = 0;

                std::cout << "\nEnter target Process ID (PID): ";

                /*
                 * Validate the supplied process identifier.
                 *
                 * Windows PIDs are represented using DWORD.
                 * Reject zero and values outside DWORD's range.
                 */
                if (!(std::cin >> inputPid) ||
                    inputPid == 0 ||
                    inputPid > std::numeric_limits<DWORD>::max())
                {
                    std::cin.clear();
                    std::cin.ignore(
                        std::numeric_limits<std::streamsize>::max(),
                        '\n'
                    );

                    std::cout << "[ERROR] Invalid PID.\n";
                    break;
                }

                /*
                 * Convert the validated input into a DWORD
                 * and attempt to open the target process.
                 */
                //scanProcess(); To be implemented.

                break;
            }

            case 0:
                std::cout << "\n[INFO] Exiting MemoryAuditor...\n";
                break;

            default:
                std::cout << "\n[ERROR] Unknown menu option.\n";
                break;
        }
    }

    return 0;
}