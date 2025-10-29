#pragma once

#include "soupbin/client.hpp"

#include "detail/event_loop.hpp"

#include "common/types.hpp"

#include <cstddef>
#include <memory>
#include <span>
#include <string>

namespace soupbin {

class client::impl {
public:
    [[nodiscard]] impl(std::unique_ptr<detail::ev_loop> loop, std::string session_id, common::seq_num_t sequence_num);

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) noexcept = default;
    impl &operator=(impl &&) noexcept = default;
    ~impl() = default;

    void send(message_type type, std::span<const std::byte>) noexcept;
    void recv(message_type &type, std::span<std::byte>) noexcept;
    [[nodiscard]] bool try_send(message_type type, std::span<const std::byte> payload) noexcept;
    [[nodiscard]] bool try_recv(message_type &type, std::span<std::byte>) noexcept;

    bool disconnect() noexcept;
    [[nodiscard]] bool connected() const noexcept;

    [[nodiscard]] const std::string &session_id() const noexcept { return session_id_; }
    [[nodiscard]] size_t sequence_num() const noexcept { return common::ts::get(sequence_num_); }

private:
    std::unique_ptr<detail::ev_loop> loop_;

    std::string session_id_;
    common::seq_num_t sequence_num_;
};

} // namespace soupbin
