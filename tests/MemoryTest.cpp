
#include <windows.h>
#include <iostream>

/*
 * MemoryTest.cpp
 *
 * Creates a controlled memory allocation for testing
 * MemoryAuditor's permission detection.
 *
 * This test does not execute code from the allocation.
 */

int main()
{
    void* memory = VirtualAlloc(
        nullptr,
        4096,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (memory == nullptr)
    {
        std::cerr << "Allocation failed: "
                  << GetLastError() << '\n';

        return 1;
    }

    std::cout << "Test process PID: " << GetCurrentProcessId() << '\n';

    std::cout << "Allocated memory at: " << memory << '\n';

    std::cout << "Press Enter to exit...\n";
    std::cin.get();

    VirtualFree(memory, 0, MEM_RELEASE);

    return 0;
}
