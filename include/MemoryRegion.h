
#pragma once

#include <windows.h>
#include <cstdint>

/*
 * MemoryRegion.h
 *
 * Represents a region of virtual memory belonging
 * to a Windows process.
 *
 * The information is obtained using VirtualQueryEx().
 */
struct MemoryRegion
{
    // Starting virtual address of the memory region.
    uintptr_t baseAddress = 0;

    /*
     * Base of the original allocation or mapped view.
     * One allocation can contain several queried regions
     * when their current protections or states differ.
     */
    std::uintptr_t allocationBase = 0;

    // Size of the region in bytes.
    SIZE_T regionSize = 0;

    // Memory state: committed, reserved, or free.
    DWORD state = 0;

    // Current protection permissions.
    DWORD protection = 0;

    // Original protection of the allocation.
    DWORD allocationProtection = 0;

    // Memory type: image, mapped, or private.
    DWORD type = 0;
};
