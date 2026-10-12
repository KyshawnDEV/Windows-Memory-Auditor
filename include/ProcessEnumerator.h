
#pragma once

#include <windows.h>
#include <string>
#include <vector>

/*
 * ProcessEnumerator.h
 *
 * Defines structures and functions used to discover
 * running Windows processes.
 *
 * Windows API:
 *   CreateToolhelp32Snapshot()
 *   Process32FirstW()
 *   Process32NextW()
 *
 * These functions allow the application to enumerate processes
 * without opening or modifying their memory.
 */

// PROCESS INFORMATION

/*
 * Represents a single running Windows process.
 *
 * pid:
 *   Unique process identifier assigned by Windows.
 *
 * name:
 *   Executable name associated with the process.
 *
 * std::wstring:
 *   Stores Unicode text using wide characters.
 *   Windows APIs frequently use wide-character strings.
 */
struct ProcessInfo
{
    DWORD pid = 0;
    std::wstring name;
};


// ============================================================
// FUNCTION DECLARATIONS
// ============================================================

/*
 * enumerateProcesses()
 *
 * Retrieves a snapshot of running processes.
 *
 * Returns:
 *   A vector containing process information.
 *
 * An empty vector can mean that no entries were
 * retrieved or that enumeration failed.
 */
std::vector<ProcessInfo> enumerateProcesses();

/*
 * displayProcesses()
 *
 * Prints the supplied process list in a table.
 */
void displayProcesses(const std::vector<ProcessInfo>& processes);
