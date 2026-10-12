
#include "Menu.h"
#include "ProcessScanner.h"

#include <iostream>
#include <limits>

/*
 * Windows Memory Auditor v0.1
 * Author: KyshawnDEV
 *
 * Purpose:
 *   Inspect the virtual memory of Windows processes to
 *   identify potentially unsafe memory configurations.
 *
 * Platform:
 *   Windows x86-64
 *
 * Compiler:
 *   MinGW-w64 / GCC
 *
 * main.cpp:
 *   Controls the application's execution flow.
 *
 * Responsibilities:
 *   - Display the main menu
 *   - Read and validate user input
 *   - Request process scans
 *   - Handle application exit
 */

// ============================================================
// MAIN FUNCTION
// ============================================================

int main()
{
    // Stores the user's current menu selection.
    int selection = -1;

    /*
     * Continue displaying the menu until the user
     * selects the exit option (0).
     */
    while (selection != 0)
    {
        // Display the application's main menu.
        displayMenu();

        // ----------------------------------------------------
        // STEP 1: READ MENU SELECTION
        // ----------------------------------------------------

        /*
         * Attempt to read an integer.
         *
         * If the user enters invalid input, clear the
         * stream error and discard the remaining characters.
         */
        if (!(std::cin >> selection))
        {
            std::cin.clear();

            std::cin.ignore(
                std::numeric_limits<std::streamsize>::max(),
                '\n'
            );

            std::cout << "\n[ERROR] Invalid selection.\n";
            continue;
        }

        // ----------------------------------------------------
        // STEP 2: EXECUTE SELECTED OPTION
        // ----------------------------------------------------

        switch (selection)
        {
            case 1:
            {
                // Stores the PID entered by the user.
                unsigned long long inputPid = 0;

                std::cout << "\nEnter target Process ID (PID): ";

                /*
                 * Validate the PID before passing it to
                 * the process-scanning component.
                 *
                 * DWORD is a 32-bit unsigned integer.
                 *
                 * Reject:
                 *   - Invalid numeric input
                 *   - PID 0
                 *   - Values exceeding DWORD's maximum
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

                // Convert the validated PID to DWORD.
                DWORD pid = static_cast<DWORD>(inputPid);

                // Request a process scan.
                scanProcess(pid);

                break;
            }

            case 0:
            {
                std::cout << "\n[INFO] Exiting MemoryAuditor...\n";
                break;
            }

            default:
            {
                std::cout << "\n[ERROR] Unknown menu option.\n";
                break;
            }
        }
    }

    return 0;
}
