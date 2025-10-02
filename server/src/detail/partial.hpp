#pragma once

#include "common/assert.hpp"

#include "detail/constants.hpp"
#include "detail/messages.hpp"

#include <array>
#include <cstddef>

namespace soupbin::detail {

class partial {
    uint8_t len_{};
    std::array<std::byte, constants::max_msg_sz> buf_{};

    static_assert(constants::max_msg_sz <= std::numeric_limits<uint8_t>::max());

public:
    void store(std::byte *input, size_t len) noexcept {
        DEBUG_ASSERT(input != nullptr);
        DEBUG_ASSERT(len <= buf_.size());
        DEBUG_ASSERT(len_ == 0);

        std::memcpy(buf_.data(), input, len);
        len_ = len;
    }

    [[nodiscard]] size_t load(std::byte *output) noexcept {
        DEBUG_ASSERT(output != nullptr);
        DEBUG_ASSERT(len_ <= buf_.size());

        size_t to_load = len_;
        len_ = 0;
        std::memcpy(output, buf_.data(), to_load);

        return to_load;
    }

    void assert_consistency() const noexcept {
        DEBUG_ASSERT(len_ <= buf_.size());

#ifndef NDEBUG
        if (len_ > sizeof(detail::msg_header)) {
            const auto *header = reinterpret_cast<const msg_header *>(buf_.data());
            switch (header->type) {
            case mt_debug:
            case mt_unsequenced:
            case mt_logout_request:
            case mt_login_request:
            case mt_client_heartbeat:
                break;

            case mt_login_accepted:
            case mt_login_rejected:
            case mt_sequenced:
            case mt_server_heartbeat:
            case mt_end_of_session:
                FUZZ_UNREACHABLE();
                break;

            default:
                ASSERT_UNREACHABLE();
                break;
            }
        }
#endif
    }
};

} // namespace soupbin::detail
