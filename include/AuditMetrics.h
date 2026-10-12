
#pragma once

/*
 * AuditMetrics.h
 *
 * Stores the number of findings discovered during
 * a Windows process memory audit.
 *
 * Severity Levels:
 *
 * Critical:
 *   Confirmed, severe security vulnerabilities.
 *
 * High:
 *   Potentially dangerous memory configurations.
 *
 * Medium:
 *   Suspicious memory configurations requiring investigation.
 *
 * Low:
 *   Informational findings or minor security concerns.
 *
 * All counters are initialized to zero.
 */

struct AuditMetrics
{
    int critical = 0;
    int high = 0;
    int medium = 0;
    int low = 0;
};
