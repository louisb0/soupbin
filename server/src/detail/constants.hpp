#pragma once

#include "soupbin/server.hpp"

#include "detail/messages.hpp"

#include <cstdint>

namespace soupbin::detail::constants {

inline constexpr uint8_t cache_line_sz = 64;
inline constexpr uint8_t max_payload_size = 2 * cache_line_sz;
inline constexpr uint8_t max_msg_sz = sizeof(detail::msg_header) + max_payload_size;

// TODO: Location.
static_assert(4 * sizeof(message_descriptor) == constants::cache_line_sz);

// TODO: Static asserts on divisibility.
namespace batch {
    inline constexpr uint16_t size = 16;

    inline constexpr uint16_t client_recv = 512;
    inline constexpr uint16_t client_data_msg = client_recv / (sizeof(detail::msg_header) + 1);
    inline constexpr uint16_t client_data_send = client_data_msg * (max_msg_sz);
} // namespace batch

namespace bound {
    inline constexpr uint16_t clients = 1024;

    inline constexpr uint16_t max_recv = batch::size * batch::client_recv;
    inline constexpr uint16_t max_data_msg = batch::size * batch::client_data_msg;
} // namespace bound

// TODO: ???
static_assert(bound::max_recv == 128 * constants::cache_line_sz);                    // NOLINT
static_assert(bound::max_data_msg == 32 * constants::cache_line_sz);                 // NOLINT
static_assert(constants::batch::client_data_send == 262 * constants::cache_line_sz); // NOLINT

} // namespace soupbin::detail::constants
