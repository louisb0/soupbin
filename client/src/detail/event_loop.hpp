#pragma once

#include "soupbin/client.hpp"

#include "common/partial.hpp"
#include "common/types.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <stop_token>
#include <thread>

namespace soupbin::detail {
class spsc_ringbuf;

class ev_loop {
public:
    [[nodiscard]] ev_loop(common::valid_fd_t fd, std::unique_ptr<detail::spsc_ringbuf> send,
                          std::unique_ptr<detail::spsc_ringbuf> recv) noexcept;
    ~ev_loop();

    ev_loop(const ev_loop &) = delete;
    ev_loop &operator=(const ev_loop &) = delete;
    ev_loop(ev_loop &&) = delete;
    ev_loop &operator=(ev_loop &&) = delete;

    void start_thread();

    void mark_disconnect(disconnect_reason reason);
    [[nodiscard]] enum disconnect_reason disconnect_reason() const noexcept;
    [[nodiscard]] bool connected() const noexcept;

    [[nodiscard]] std::jthread &thread() noexcept { return thread_; }
    [[nodiscard]] detail::spsc_ringbuf &send_rb() noexcept { return *send_; }
    [[nodiscard]] detail::spsc_ringbuf &recv_rb() noexcept { return *recv_; }

private:
    common::valid_fd_t fd_;
    common::partial partial_;

    std::jthread thread_;
    std::unique_ptr<detail::spsc_ringbuf> send_;
    std::unique_ptr<detail::spsc_ringbuf> recv_;
    std::atomic<enum disconnect_reason> disconnect_reason_;

    std::chrono::steady_clock::time_point last_send_{ std::chrono::steady_clock::now() };
    std::chrono::steady_clock::time_point last_recv_{ std::chrono::steady_clock::now() };

    void run(const std::stop_token &token) noexcept;
};

} // namespace soupbin::detail
