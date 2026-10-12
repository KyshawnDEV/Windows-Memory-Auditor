
#include "ProcessEnumerator.h"
#include "WindowsHandle.h"

#include <tlhelp32.h>
#include <algorithm>
#include <iomanip>
#include <iostream>

/*
 * ProcessEnumerator.cpp
 *
 * Implements Windows process enumeration.
 *
 * Uses the Windows Tool Help API to obtain a snapshot
 * of currently running processes.
 *
 * The snapshot contains process metadata, including:
 *   - Process ID
 *   - Executable name
 *
 * This component does not inspect or modify process memory.
 */

// ============================================================
// ENUMERATE PROCESSES
// ============================================================

std::vector<ProcessInfo> enumerateProcesses()
{
    // Stores all discovered processes.
    std::vector<ProcessInfo> processes;

    // --------------------------------------------------------
    // STEP 1: CREATE PROCESS SNAPSHOT
    // --------------------------------------------------------

    /*
     * CreateToolhelp32Snapshot() creates a snapshot
     * containing information about running processes.
     *
     * TH32CS_SNAPPROCESS:
     *   Requests process information.
     *
     * 0:
     *   Ignored when TH32CS_SNAPPROCESS is specified.
     */
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    /*
     * Unlike OpenProcess(), this function indicates
     * failure using INVALID_HANDLE_VALUE.
     */
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        DWORD errorCode = GetLastError();
        std::cerr << "[ERROR] Failed to create process snapshot.\n";
        std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';

        return processes;
    }

    // Release the snapshot even if storing a process entry throws.
    WindowsHandle snapshotHandle(snapshot);

    // --------------------------------------------------------
    // STEP 2: PREPARE PROCESS ENTRY
    // --------------------------------------------------------

    /*
     * PROCESSENTRY32W stores information about one process.
     *
     * The W suffix indicates the Unicode version.
     *
     * dwSize must be initialized before calling
     * Process32FirstW().
     */
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    // --------------------------------------------------------
    // STEP 3: ENUMERATE PROCESS ENTRIES
    // --------------------------------------------------------

    /*
     * Process32FirstW() retrieves the first entry.
     *
     * Process32NextW() advances to subsequent entries.
     *
     * Enumeration continues until there are no more entries.
     */
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            ProcessInfo process;

            // Store the process identifier.
            process.pid = entry.th32ProcessID;

            // Store the executable name.
            process.name = entry.szExeFile;

            // Add the discovered process to our vector.
            processes.push_back(process);

        } while (Process32NextW(snapshot, &entry));

        /*
         * ERROR_NO_MORE_FILES indicates normal completion.
         * Other errors mean the collected list may be partial.
         * Preserve the error before console output can change it.
         */
        DWORD errorCode = GetLastError();

        if (errorCode != ERROR_NO_MORE_FILES)
        {
            std::cerr << "[WARNING] Process enumeration stopped early.\n";
            std::cerr << "[WARNING] The process list may be incomplete.\n";
            std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';
        }
    }
    else
    {
        DWORD errorCode = GetLastError();

        // An empty snapshot is different from an enumeration failure.
        if (errorCode != ERROR_NO_MORE_FILES)
        {
            std::cerr << "[ERROR] Failed to read process snapshot.\n";
            std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';
        }
    }

    // --------------------------------------------------------
    // STEP 4: RELEASE SNAPSHOT HANDLE
    // --------------------------------------------------------

    /*
     * The snapshot is a Windows-managed resource.
     *
     * Explicit cleanup releases it after enumeration.
     * Scope cleanup also handles exceptions and early returns.
     */
    if (!snapshotHandle.close())
    {
        DWORD errorCode = GetLastError();
        std::cerr << "[ERROR] Unable to close process snapshot.\n";
        std::cerr << "[ERROR] Windows error code: " << errorCode << '\n';
    }

    // --------------------------------------------------------
    // STEP 5: SORT PROCESSES BY PID
    // --------------------------------------------------------

    /*
     * std::sort() arranges entries in ascending PID order.
     *
     * The lambda compares two ProcessInfo objects.
     */
    std::sort(
        processes.begin(),
        processes.end(),
        [](const ProcessInfo& a, const ProcessInfo& b)
        {
            return a.pid < b.pid;
        }
    );

    return processes;
}


// ============================================================
// DISPLAY PROCESSES
// ============================================================

void displayProcesses(const std::vector<ProcessInfo>& processes)
{
    std::wcout << L"\n================ RUNNING PROCESSES ================\n\n";

    std::wcout << std::left
               << std::setw(14) << L"PID"
               << L"PROCESS NAME\n";

    std::wcout << L"---------------------------------------------------\n";

    /*
     * Iterate through each discovered process.
     *
     * const ProcessInfo&:
     *   Avoids copying each object.
     *
     * const:
     *   Prevents modification of the original entry.
     */
    for (const ProcessInfo& process : processes)
    {
        std::wcout << std::left
                   << std::setw(14) << process.pid
                   << process.name << L'\n';
    }

    std::wcout << L"\nTotal processes found: "
               << processes.size() << L'\n';
}
