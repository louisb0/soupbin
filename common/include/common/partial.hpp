#pragma once

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/messages.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <limits>

namespace soupbin::common {

class partial {
public:
    using size_type = uint8_t;

    struct client_tag {};
    struct server_tag {};

private:
    static_assert(common::max_message_size <= std::numeric_limits<size_type>::max());

    std::array<std::byte, common::max_message_size> buffer_{};
    size_type length_{};

public:
    template <typename Tag>
        requires std::is_same_v<Tag, partial::client_tag> || std::is_same_v<Tag, partial::server_tag>
    void store(std::byte *input, size_type length, Tag /*tag*/) noexcept {
        DEBUG_ASSERT(input != nullptr);
        DEBUG_ASSERT(length_ == 0);
        DEBUG_ASSERT(length <= buffer_.size());

        std::memcpy(buffer_.data(), input, length);
        length_ = static_cast<uint8_t>(length);

#ifndef NDEBUG
        if (length_ > sizeof(common::msg_header)) {
            const auto *header = reinterpret_cast<const common::msg_header *>(buffer_.data());

            if constexpr (std::is_same_v<Tag, server_tag>) {
                // NOTE: If running on the server, the parital can only store client messages.
                switch (header->type) {
                case common::mt_debug:
                case common::mt_unsequenced:
                case common::mt_logout_request:
                case common::mt_login_request:
                case common::mt_client_heartbeat:
                    break;

                case common::mt_login_accepted:
                case common::mt_login_rejected:
                case common::mt_sequenced:
                case common::mt_server_heartbeat:
                case common::mt_end_of_session:
                    FUZZ_UNREACHABLE();
                    break;

                default:
                    ASSERT_UNREACHABLE();
                    break;
                }
            } else {
                // NOTE: If running on the client, the parital can only store server messages.
                switch (header->type) {
                case common::mt_debug:
                case common::mt_unsequenced:
                case common::mt_sequenced:
                case common::mt_login_accepted:
                case common::mt_login_rejected:
                case common::mt_server_heartbeat:
                case common::mt_end_of_session:
                    break;

                case common::mt_logout_request:
                case common::mt_login_request:
                case common::mt_client_heartbeat:
                    FUZZ_UNREACHABLE();
                    break;

                default:
                    ASSERT_UNREACHABLE();
                    break;
                }
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

} // namespace soupbin::common
