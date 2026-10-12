
#include "Menu.h"

#include <iostream>

/*
 * Menu.cpp
 *
 * Implements the console interface for MemoryAuditor.
 *
 * Version 0.2 adds process enumeration.
 */

void displayMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       WINDOWS MEMORY AUDITOR v0.2\n";
    std::cout << "========================================\n\n";

    std::cout << "[1] List running processes\n";
    std::cout << "[2] Scan a process by PID\n";
    std::cout << "[0] Exit\n\n";

    std::cout << "Make your menu selection now: ";
}
