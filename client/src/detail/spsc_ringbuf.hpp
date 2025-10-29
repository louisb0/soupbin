#pragma once

#include "common/config.hpp"

#include <atomic>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>

namespace soupbin::detail {

class spsc_ringbuf {
public:
    static std::expected<std::unique_ptr<spsc_ringbuf>, std::error_code> create(size_t capacity) noexcept;
    [[nodiscard]] spsc_ringbuf(std::byte *base, size_t capacity) noexcept;

    spsc_ringbuf(const spsc_ringbuf &) = delete;
    spsc_ringbuf &operator=(const spsc_ringbuf &) = delete;
    spsc_ringbuf(spsc_ringbuf &&) = delete;
    spsc_ringbuf &operator=(spsc_ringbuf &&) = delete;
    ~spsc_ringbuf() noexcept;

    [[nodiscard]] std::span<const std::byte> read_try_prepare() noexcept;
    [[nodiscard]] std::span<const std::byte> read_prepare() noexcept;
    void read_commit(size_t bytes) noexcept;

    [[nodiscard]] std::byte *write_try_prepare(size_t bytes) noexcept;
    [[nodiscard]] std::byte *write_prepare(size_t bytes) noexcept;
    void write_commit(size_t bytes) noexcept;

private:
    std::byte *base_;
    size_t capacity_;

    alignas(common::cache_line_size) std::atomic<size_t> read_cursor_{ 0 };
    alignas(common::cache_line_size) size_t read_cursor_cache_{ 0 };
    alignas(common::cache_line_size) std::atomic<size_t> write_cursor_{ 0 };
    alignas(common::cache_line_size) size_t write_cursor_cache_{ 0 };
    static_assert(std::atomic<size_t>::is_always_lock_free);

    [[nodiscard]] std::byte *primary() const noexcept { return base_; }
    [[nodiscard]] std::byte *mirror() const noexcept { return base_ + capacity_; }

    [[nodiscard]] static bool empty(size_t read_cursor, size_t write_cursor) noexcept { return read_cursor == write_cursor; }
    [[nodiscard]] static size_t size(size_t read_cursor, size_t write_cursor) noexcept { return write_cursor - read_cursor; }
};

}; // namespace soupbin::detail
