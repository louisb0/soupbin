#pragma once

#include "soupbin/client.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace soupbin {

class client::impl {
public:
    [[nodiscard]] impl() noexcept;

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;
    ~impl() = default;

    void recv(std::span<std::byte>) noexcept;
    [[nodiscard]] bool try_recv(std::span<std::byte>) noexcept;
    [[nodiscard]] bool send(message_type type, std::span<const std::byte> payload) noexcept;

    void disconnect() noexcept;
    [[nodiscard]] bool connected() const noexcept { return false; } // NOLINT

    [[nodiscard]] const std::string &session_id() const noexcept { return session_id_; }
    [[nodiscard]] size_t sequence_num() const noexcept { return sequence_num_; };

private:
    std::string session_id_;
    uint64_t sequence_num_;

    void assert_consistency() const noexcept;
};

} // namespace soupbin
