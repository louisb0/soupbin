#pragma once

#include "soupbin/server.hpp"

#include "detail/constants.hpp"

#include <cstdint>
#include <limits>
#include <utility>

namespace soupbin::detail {

template <typename T, typename Tag>
class strong_type {
public:
    constexpr explicit strong_type(const T &value) : value_(value) {}
    constexpr explicit strong_type(T &&value) : value_(std::move(value)) {}

    [[nodiscard]] constexpr T &get() noexcept { return value_; }
    [[nodiscard]] constexpr const T &get() const noexcept { return value_; }

private:
    T value_{};
};

using valid_fd_t = strong_type<uint16_t, struct valid_fd>;
using client_handle_t = strong_type<uint16_t, struct valid_fd>;

// NOTE: client_handle_t must be able to index all clients.
static_assert(constants::bound::clients <= std::numeric_limits<uint16_t>::max());

} // namespace soupbin::detail
