
#include "Menu.h"

#include <iostream>

/*
 * Menu.cpp
 *
 * Implements the application's console menu.
 *
 * Future versions may include:
 *   - List running processes
 *   - Scan processes by name
 *   - View previous scan results
 *   - Configure audit settings
 */

/*
 * Displays the main menu for the Windows Memory Auditor.
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
