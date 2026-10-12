#pragma once

/*
 * MemoryExposure.h
 *
 * Describes the memory configuration observed in one region.
 * These categories describe potential storage or execution
 * exposure, not malware or confirmed injection opportunities.
 */
enum class ExposureCategory
{
    None,
    UnknownProtection,
    Writable,
    CopyOnWrite,
    PrivateExecutable,
    PrivateWritableExecutable,
    ImageExecutable,
    ImageWritableExecutable,
    MappedExecutable,
    MappedWritableExecutable,
    ExecutableCopyOnWrite,
    OtherExecutable,
    OtherWritableExecutable
};

// Priority controls investigation order, not vulnerability severity.
enum class InvestigationPriority
{
    None,
    Low,
    Medium,
    High
};

struct MemoryExposure
{
    ExposureCategory category = ExposureCategory::None;
    InvestigationPriority priority = InvestigationPriority::None;

    // Base permissions are retained even when PAGE_GUARD is present.
    bool executable = false;
    bool writable = false;
    bool copyOnWrite = false;
    bool guarded = false;
};
