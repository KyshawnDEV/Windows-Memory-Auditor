#include <iostream>
#include <windows.h>

/*
 * Windows Memory Auditor v0.1
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

int main()
{
    int choice;
    do {
        displayMenu();
        std::cin >> choice;

        switch (choice) {
            case 1:
                std::cout << "Scanning a process...\n";
                break;
            case 0:
                std::cout << "Exiting...\n";
                break;
            default:
                std::cout << "Invalid menu selection. Please try again.\n";
                break;
        }
    } while (choice != 0);

    return 0;
}