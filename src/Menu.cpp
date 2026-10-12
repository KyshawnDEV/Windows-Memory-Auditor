
#include "Menu.h"

#include <iostream>

/*
 * Menu.cpp
 *
 * Implements the console interface for MemoryAuditor.
 *
 * Current Features:
 *   - Display the application name and version
 *   - List the process enumeration and scanning options
 *   - Display the exit option and selection prompt
 *
 * Menu input and program control are handled by main.cpp.
 */

void displayMenu()
{
    std::cout << "\n========================================\n";
    std::cout << "       WINDOWS MEMORY AUDITOR v0.8\n";
    std::cout << "========================================\n\n";

    std::cout << "[1] List running processes\n";
    std::cout << "[2] Scan a process by PID\n";
    std::cout << "[3] Assess current-caller process access by PID\n";
    std::cout << "[0] Exit\n\n";

    std::cout << "Make your menu selection now: ";
}
