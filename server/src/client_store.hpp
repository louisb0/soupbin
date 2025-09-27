#pragma once

#include "soupbin/server.hpp"

#include "constants.hpp"
#include "types.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include <sys/epoll.h>

namespace soupbin {
class session;

struct cl_loop_info {
    session *sess;
    valid_fd_t fd;
    client_handle_t handle;

    struct {
        uint8_t len;
        // TODO: Enforce this on the client callback.
        // TODO: Use the header size directly instead of 3.
        std::array<std::byte, 3 + (2UZ * constants::cache_line_bytes)> buf;
    } partial;

    [[nodiscard]] bool authed() const noexcept { return sess != nullptr; }
};

struct cl_activity_info {
    std::chrono::steady_clock::time_point last_send;
    std::chrono::steady_clock::time_point last_recv;
};

union cl_epoll_data {
    uint32_t u32;
    struct {
        uint16_t fd;
        uint16_t handle;
    } parts;
};
static_assert(sizeof(decltype(std::declval<valid_fd_t>().get())) == sizeof(cl_epoll_data::parts.fd));
static_assert(sizeof(decltype(std::declval<client_handle_t>().get())) == sizeof(cl_epoll_data::parts.handle));

class client_store {
    const valid_fd_t epoll_;
    const client_handle_t max_clients_;

    std::vector<cl_loop_info> loop_info_;
    std::vector<cl_activity_info> activity_info_;

    std::array<epoll_event, SOUPBIN_BATCH_SIZE> event_buffer_{};
    std::array<cl_loop_info *, SOUPBIN_BATCH_SIZE> ready_buffer_{};

public:
    [[nodiscard]] client_store(valid_fd_t epoll, client_handle_t max_clients) noexcept;
    ~client_store();

    client_store(client_store &) = delete;
    client_store &operator=(client_store &) = delete;
    client_store(client_store &&) = delete;
    client_store &operator=(client_store &&) = delete;

    [[nodiscard]] std::span<cl_loop_info *> ready(int timeout_ms) noexcept;
    void add(std::span<const valid_fd_t>) noexcept;
    void remove(std::span<client_handle_t>) noexcept;

    [[nodiscard]] std::span<const cl_activity_info> activity() const noexcept;
    [[nodiscard]] cl_activity_info &activity_info(client_handle_t) noexcept;
    [[nodiscard]] bool full() const noexcept;
    [[nodiscard]] size_t size() const noexcept;

    void assert_consistency() const noexcept;
};

} // namespace soupbin
