
#include "Menu.h"

#include <iostream>

/*
 * Menu.cpp
 *
 * Implements the console interface for MemoryAuditor.
 *
 * Version 0.4 adds:
 *   - Scan completion tracking
 *   - Memory usage statistics
 *   - Memory region display filters
 *   - Expanded audit summaries
 */

void displayMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       WINDOWS MEMORY AUDITOR v0.4\n";
    std::cout << "========================================\n\n";

    std::cout << "[1] List running processes\n";
    std::cout << "[2] Scan a process by PID\n";
    std::cout << "[0] Exit\n\n";

    std::cout << "Make your menu selection now: ";
}
