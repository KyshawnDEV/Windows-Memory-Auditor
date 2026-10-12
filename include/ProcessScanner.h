
#pragma once

#include <windows.h>

/*
 * ProcessScanner.h
 *
 * Declares functionality for inspecting Windows processes.
 *
 * Current Features:
 *   - Open a process using its PID
 *   - Request query access to process metadata
 *   - Enumerate committed virtual memory regions
 *   - Calculate memory statistics
 *   - Record W+X findings requiring review
 *   - Select a memory region display filter
 *   - Display scan status and audit results
 *   - Release the process handle
 *
 * Memory enumeration, analysis, and reporting are
 * implemented by the MemoryScanner component.
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
 * Opens the target with PROCESS_QUERY_INFORMATION,
 * coordinates scanning and reporting, and releases
 * the process handle after the scan.
 *
 * Query access does not establish permission to write
 * to the target process's memory. This function does
 * not read or modify memory contents.
 */
void scanProcess(DWORD pid);
