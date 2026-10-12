
#pragma once

#include <windows.h>

class ScanHistory;

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
 *   - Record memory exposure investigation priorities
 *   - Select a memory region display filter
 *   - Display scan status and audit results
 *   - Collect and display allocation, module, and mapped-file context
 *   - Compare repeated scans against session baselines
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
 *   history - Complete baselines retained by the main program.
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
void scanProcess(DWORD pid, ScanHistory& history);
