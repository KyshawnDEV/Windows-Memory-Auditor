#pragma once

#include <windows.h>

/*
 * WindowsHandle.h
 *
 * Owns one Windows handle and releases it when the object
 * leaves scope, including when an exception interrupts work.
 *
 * This follows Resource Acquisition Is Initialization (RAII):
 *   The lifetime of the object controls the handle's lifetime.
 *
 * Copying is disabled because two owners must not close
 * the same handle. The handle can also be closed explicitly
 * when the caller needs to report a cleanup error.
 */
class WindowsHandle
{
public:
    explicit WindowsHandle(HANDLE handle) noexcept
        : handle_(handle)
    {
    }

    ~WindowsHandle()
    {
        close();
    }

    WindowsHandle(const WindowsHandle&) = delete;
    WindowsHandle& operator=(const WindowsHandle&) = delete;

    /*
     * close()
     *
     * Releases an owned handle and clears ownership on success.
     * Null and INVALID_HANDLE_VALUE are not owned resources.
     *
     * On failure, GetLastError() provides the Windows error code.
     * Ownership is retained so scope cleanup can retry.
     */
    bool close() noexcept
    {
        if (handle_ == nullptr || handle_ == INVALID_HANDLE_VALUE)
            return true;

        if (!CloseHandle(handle_))
            return false;

        handle_ = nullptr;
        return true;
    }

private:
    HANDLE handle_ = nullptr;
};
