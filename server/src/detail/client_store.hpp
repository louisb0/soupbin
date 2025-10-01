#pragma once

#include "detail/constants.hpp"
#include "detail/types.hpp"
#include "detail/verify.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

#include <sys/epoll.h>

namespace soupbin::detail {
class session;

struct cl_activity_info {
    std::chrono::steady_clock::time_point last_send;
    std::chrono::steady_clock::time_point last_recv;
};

struct cl_loop_info {
    detail::session *sess{};
    detail::valid_fd_t fd{ 0 };
    detail::client_handle_t handle{ 0 };

    struct {
        uint8_t len;
        std::array<std::byte, constants::max_msg_sz> buf;
    } partial{};

    [[nodiscard]] bool authed() const noexcept { return sess != nullptr; }
};

union cl_epoll_data {
    uint64_t u64{};
    struct {
        uint16_t fd;
        uint16_t handle;
        uint32_t _reserved{ 0 };
    } parts;

    static_assert(sizeof(decltype(std::declval<valid_fd_t>().get())) == sizeof(cl_epoll_data::parts.fd));
    static_assert(sizeof(decltype(std::declval<client_handle_t>().get())) == sizeof(cl_epoll_data::parts.handle));
};

static_assert(verify::no_padding<cl_activity_info>());
static_assert(verify::no_padding<cl_loop_info>());
static_assert(verify::no_padding<cl_epoll_data>());

class client_store {
    const detail::valid_fd_t epoll_;
    const detail::client_handle_t max_clients_;

    std::vector<cl_loop_info> loop_info_;
    std::vector<cl_activity_info> activity_info_;

    std::array<epoll_event, constants::batch::size> event_buffer_{};
    std::array<cl_loop_info *, constants::batch::size> ready_buffer_{};

public:
    [[nodiscard]] client_store(valid_fd_t epoll, client_handle_t max_clients) noexcept;
    ~client_store();

    client_store(client_store &) = delete;
    client_store &operator=(client_store &) = delete;
    client_store(client_store &&) = delete;
    client_store &operator=(client_store &&) = delete;

    void add(std::span<const valid_fd_t>) noexcept;
    void remove(std::span<client_handle_t>) noexcept;

    struct ready_clients {
        std::span<cl_loop_info *> authed;
        std::span<cl_loop_info *> unauthed;
    };
    [[nodiscard]] ready_clients ready(int timeout_ms) noexcept;

    [[nodiscard]] cl_activity_info &activity(client_handle_t) noexcept;
    [[nodiscard]] std::span<const cl_activity_info> activity() const noexcept;

    [[nodiscard]] bool full() const noexcept;
    [[nodiscard]] size_t size() const noexcept;

    void assert_consistency() const noexcept;
};

} // namespace soupbin::detail
