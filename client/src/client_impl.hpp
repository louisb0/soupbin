#pragma once

#include "soupbin/client.hpp"

#include "detail/event_loop.hpp"

#include "common/types.hpp"

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>

namespace soupbin {

class client::impl {
    friend class client;

public:
    [[nodiscard]] impl(std::unique_ptr<detail::ev_loop> loop, std::string session_id,
                       common::seq_num_t sequence_num) noexcept;

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) noexcept = default;
    impl &operator=(impl &&) noexcept = default;
    ~impl() = default;

    template <typename AcquirePosition>
    std::optional<std::error_code> send_impl(message_type type, std::span<const std::byte> payload,
                                             AcquirePosition acq_position);
    template <typename AcquireSlot>
    std::optional<std::error_code> recv_impl(message_type &type, std::span<std::byte> buffer, size_t &bytes,
                                             AcquireSlot acq_slot);

private:
    std::unique_ptr<detail::ev_loop> event_loop_;
    std::string session_id_;
    common::seq_num_t sequence_num_;
};

} // namespace soupbin
