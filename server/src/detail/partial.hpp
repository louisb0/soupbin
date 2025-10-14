#pragma once

#include "detail/config.hpp"
#include "detail/messages.hpp"

#include "common/assert.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <limits>

namespace soupbin::detail {

// TODO: Shared with client module - should be extracted alongside messages.

template <size_t N>
class partial {
public:
    using size_type = uint8_t;

private:
    static_assert(N <= std::numeric_limits<size_type>::max());

    std::array<std::byte, N> buffer_{};
    size_type length_{};

public:
    void store(std::byte *input, size_type length) noexcept {
        DEBUG_ASSERT(input != nullptr);
        DEBUG_ASSERT(length_ == 0);
        DEBUG_ASSERT(length <= buffer_.size());

        std::memcpy(buffer_.data(), input, length);
        length_ = static_cast<uint8_t>(length);

#ifndef NDEBUG
        if (length_ > sizeof(detail::msg_header)) {
            const auto *header = reinterpret_cast<const detail::msg_header *>(buffer_.data());

            switch (header->type) {
            case detail::mt_debug:
            case detail::mt_unsequenced:
            case detail::mt_logout_request:
            case detail::mt_login_request:
            case detail::mt_client_heartbeat:
                break;

            case detail::mt_login_accepted:
            case detail::mt_login_rejected:
            case detail::mt_sequenced:
            case detail::mt_server_heartbeat:
            case detail::mt_end_of_session:
                FUZZ_UNREACHABLE();
                break;

            default:
                ASSERT_UNREACHABLE();
                break;
            }
        }
#endif
    }

    [[nodiscard]] size_type load(std::byte *output) noexcept {
        DEBUG_ASSERT(output != nullptr);

        std::memcpy(output, buffer_.data(), length_);
        const size_type loaded = length_;
        length_ = 0;

        return loaded;
    }
};

} // namespace soupbin::detail
