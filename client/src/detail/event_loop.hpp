#pragma once

#include "detail/config.hpp"

#include "common/types.hpp"

#include <atomic>
#include <memory>
#include <stop_token>
#include <system_error>
#include <thread>

namespace soupbin::detail {
class spsc_ringbuf;

class ev_loop {
public:
    [[nodiscard]] ev_loop(common::valid_fd_t fd, std::unique_ptr<detail::spsc_ringbuf> send,
                          std::unique_ptr<detail::spsc_ringbuf> recv) noexcept;

    ev_loop(const ev_loop &) = delete;
    ev_loop &operator=(const ev_loop &) = delete;
    ev_loop(ev_loop &&) = delete;
    ev_loop &operator=(ev_loop &&) = delete;
    ~ev_loop();

    void start_thread();

    [[nodiscard]] std::error_code error() const noexcept;
    [[nodiscard]] std::jthread &thread() noexcept { return thread_; }
    [[nodiscard]] const std::jthread &thread() const noexcept { return thread_; }
    [[nodiscard]] detail::spsc_ringbuf &send() noexcept { return *send_; }
    [[nodiscard]] detail::spsc_ringbuf &recv() noexcept { return *recv_; }

private:
    std::atomic<int> errno_{ detail::no_error };

    common::valid_fd_t fd_;
    std::jthread thread_;
    std::unique_ptr<detail::spsc_ringbuf> send_;
    std::unique_ptr<detail::spsc_ringbuf> recv_;

    void run(const std::stop_token &token) noexcept;
};

} // namespace soupbin::detail
