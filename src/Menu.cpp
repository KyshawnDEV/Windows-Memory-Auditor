
#include "Menu.h"

#include <iostream>

/*
 * Menu.cpp
 *
 * Implements the console interface for MemoryAuditor.
 *
 * Version 0.2 adds process enumeration.
 * 
 *  * Version 0.3 adds:
 *   - Virtual memory region enumeration
 *   - Memory protection and type identification
 *   - Detection of writable/executable (W+X) memory regions
 *   - Audit metrics and severity reporting
 */

void displayMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       WINDOWS MEMORY AUDITOR v0.3\n";
    std::cout << "========================================\n\n";

    std::cout << "[1] List running processes\n";
    std::cout << "[2] Scan a process by PID\n";
    std::cout << "[0] Exit\n\n";

    std::cout << "Make your menu selection now: ";
}
