#pragma once

#include "soupbin/client.hpp"

#include "common/types.hpp"

#include <cstddef>
#include <span>
#include <stop_token>
#include <string>
#include <thread>

namespace soupbin {

class client::impl {
public:
    [[nodiscard]] impl(common::valid_fd_t fd, std::string session_id, common::seq_num_t sequence_num);

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;
    ~impl() = default;

    void send(message_type type, std::span<const std::byte>) noexcept;
    void recv(message_type &type, std::span<std::byte>) noexcept;
    [[nodiscard]] bool try_send(message_type type, std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool try_recv(message_type &type, std::span<std::byte>) noexcept;

    bool disconnect() noexcept { return thread_.request_stop(); }
    [[nodiscard]] bool connected() const noexcept { return !thread_.get_stop_token().stop_requested(); }

    [[nodiscard]] const std::string &session_id() const noexcept { return session_id_; }
    [[nodiscard]] size_t sequence_num() const noexcept { return common::ts::get(sequence_num_); }

private:
    std::jthread thread_;
    common::valid_fd_t fd_;

    std::string session_id_;
    common::seq_num_t sequence_num_;

    void run(const std::stop_token &token) noexcept;

    void assert_consistency() const noexcept;
};

} // namespace soupbin
