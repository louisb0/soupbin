#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/messages.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>

#include <sys/mman.h>

namespace soupbin::detail {

std::expected<spsc_ringbuf, std::error_code> spsc_ringbuf::create(size_t capacity) noexcept {
    ASSERT(capacity >= common::max_message_size);
    ASSERT(capacity % common::page_size == 0);
    static_assert(common::page_size % 2 == 0);

    // Create identifying file descriptor.
    int fd = memfd_create("spsc_ringbuf", 0);
    if (fd == -1) {
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    if (ftruncate(fd, static_cast<off_t>(capacity)) != 0) {
        int saved_errno = errno;
        close(fd);
        return std::unexpected(std::error_code(saved_errno, std::system_category()));
    }

    // Map contiguous region.
    const size_t total_size = capacity * 2;
    void *region = mmap(nullptr, total_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (region == MAP_FAILED) {
        int saved_errno = errno;
        close(fd);
        return std::unexpected(std::error_code(saved_errno, std::system_category()));
    }

    // Map primary and mirror sub-regions.
    void *primary = mmap(region, capacity, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (primary == MAP_FAILED) {
        int saved_errno = errno;
        munmap(region, total_size);
        close(fd);
        return std::unexpected(std::error_code(saved_errno, std::system_category()));
    }

    void *mirror =
        mmap(static_cast<std::byte *>(region) + capacity, capacity, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, 0);
    if (mirror == MAP_FAILED) {
        int saved_errno = errno;
        munmap(region, total_size);
        close(fd);
        return std::unexpected(std::error_code(saved_errno, std::system_category()));
    }

    close(fd);

    return std::expected<spsc_ringbuf, std::error_code>(std::in_place, static_cast<std::byte *>(primary), capacity);
}

spsc_ringbuf::spsc_ringbuf(std::byte *base, size_t capacity) noexcept : base_(base), capacity_(capacity) {
    ASSERT(base != nullptr);
    ASSERT(capacity >= common::max_message_size);
    ASSERT(capacity % common::page_size == 0);
}

spsc_ringbuf::~spsc_ringbuf() noexcept {
    if (munmap(primary(), capacity_) == -1) {
        LOG_ERROR("failed to unmap primary buffer: {}", std::strerror(errno));
    }

    if (munmap(mirror(), capacity_) == -1) {
        LOG_ERROR("failed to unmap mirrored buffer: {}", std::strerror(errno));
    }
}

std::span<const std::byte> spsc_ringbuf::read_try_prepare() noexcept {
    auto read_cursor = read_cursor_.load(std::memory_order_relaxed);
    if (empty(read_cursor, write_cursor_cache_)) {
        write_cursor_cache_ = write_cursor_.load(std::memory_order_acquire);
        if (empty(read_cursor, write_cursor_cache_)) {
            return {};
        }
    }

    auto read_index = read_cursor & (capacity_ - 1);
    auto readable = size(read_cursor, write_cursor_cache_);
    return { primary() + read_index, readable };
}

std::span<const std::byte> spsc_ringbuf::read_prepare() noexcept {
    auto read_cursor = read_cursor_.load(std::memory_order_relaxed);
    while (empty(read_cursor, write_cursor_cache_)) {
        write_cursor_cache_ = write_cursor_.load(std::memory_order_acquire);
    }

    auto read_index = read_cursor & (capacity_ - 1);
    auto readable = size(read_cursor, write_cursor_cache_);
    return { primary() + read_index, readable };
}

void spsc_ringbuf::read_commit(size_t bytes) noexcept {
#ifndef NDEBUG
    auto read_cursor = read_cursor_.load(std::memory_order_relaxed);
    DEBUG_ASSERT(!empty(read_cursor, write_cursor_cache_));
    DEBUG_ASSERT(size(read_cursor, write_cursor_cache_) >= bytes);
    read_cursor_.store(read_cursor + bytes, std::memory_order_release);
#else
    read_cursor_.fetch_add(bytes, std::memory_order_release);
#endif
}

std::byte *spsc_ringbuf::write_try_prepare(size_t bytes) noexcept {
    DEBUG_ASSERT(bytes <= capacity_);

    auto write_cursor = write_cursor_.load(std::memory_order_relaxed);
    if (capacity_ - size(read_cursor_cache_, write_cursor) < bytes) {
        read_cursor_cache_ = read_cursor_.load(std::memory_order_acquire);
        if (capacity_ - size(read_cursor_cache_, write_cursor) < bytes) {
            return nullptr;
        }
    }

    auto write_index = write_cursor & (capacity_ - 1);
    return primary() + write_index;
}

std::byte *spsc_ringbuf::write_prepare(size_t bytes) noexcept {
    DEBUG_ASSERT(bytes <= capacity_);

    auto write_cursor = write_cursor_.load(std::memory_order_relaxed);
    while (capacity_ - size(read_cursor_cache_, write_cursor) < bytes) {
        read_cursor_cache_ = read_cursor_.load(std::memory_order_acquire);
    }

    auto write_index = write_cursor & (capacity_ - 1);
    return primary() + write_index;
}

void spsc_ringbuf::write_commit(size_t bytes) noexcept {
#ifndef NDEBUG
    auto write_cursor = write_cursor_.load(std::memory_order_relaxed);
    DEBUG_ASSERT(capacity_ - size(read_cursor_cache_, write_cursor) >= bytes);
    write_cursor_.store(write_cursor + bytes, std::memory_order_release);
#else

    write_cursor_.fetch_add(bytes, std::memory_order_release);
#endif
}

}; // namespace soupbin::detail
