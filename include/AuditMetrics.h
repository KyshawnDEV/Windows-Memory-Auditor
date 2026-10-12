
#pragma once

#include <cstddef>

/*
 * AuditMetrics.h
 *
 * Stores region counts by investigation priority.
 *
 * Investigation Priorities:
 *
 * High:
 *   Private memory with ordinary write and execute permissions.
 *
 * Medium:
 *   Other ordinary W+X memory, or private executable memory.
 *
 * Low:
 *   Executable copy-on-write, executable memory of unknown type,
 *   or an unrecognized base protection requiring clarification.
 *
 * A region contributes to at most one priority counter.
 * Priorities do not establish external access, exploitability,
 * malicious intent, or a confirmed vulnerability.
 *
 * All counters are initialized to zero.
 */

struct AuditMetrics
{
    std::size_t high = 0;
    std::size_t medium = 0;
    std::size_t low = 0;
};
