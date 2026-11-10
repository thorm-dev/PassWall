#pragma once

// Test fixtures only: complete the intended bytes, not the intentionally
// malformed protocol they may contain. Writes use blocking descriptors;
// a nonblocking error is returned too, never retried in a busy loop.
#include <cerrno>
#include <cstddef>
#include <unistd.h>

namespace passwall::test_io {
[[nodiscard]] inline bool writeAll(int fd, const void* data, std::size_t size) noexcept
{
    const auto* bytes = static_cast<const char*>(data);
    while (size != 0) {
        const auto count = ::write(fd, bytes, size);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false; // No retry/spin after a real I/O error.
        bytes += count;
        size -= static_cast<std::size_t>(count);
    }
    return true;
}

[[nodiscard]] inline ssize_t readSome(int fd, void* data, std::size_t size) noexcept
{
    ssize_t count;
    do { count = ::read(fd, data, size); } while (count < 0 && errno == EINTR);
    return count; // Caller must distinguish bytes, EOF and error.
}
} // namespace passwall::test_io
