
#pragma once

#include <windows.h>

/*
 * ProcessScanner.h
 *
 * Declares functionality for inspecting Windows processes.
 *
 * Current Features:
 *   - Open a process using its PID
 *   - Verify process access
 *   - Release the process handle
 *
 * Future Features:
 *   - Enumerate virtual memory regions
 *   - Inspect memory protection flags
 *   - Identify potentially unsafe memory configurations
 *   - Record audit findings
 */

/*
 * scanProcess()
 *
 * Parameters:
 *   pid - Process ID of the target Windows application.
 *
 * Returns:
 *   void
 *
 * This function currently opens and closes a process.
 * Memory scanning will be implemented later.
 */
void scanProcess(DWORD pid);
