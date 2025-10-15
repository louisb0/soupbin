#pragma once

#include "common/assert.hpp"

#include <cstdint>
#include <cstring>
#include <string_view>

#include <arpa/inet.h>

namespace soupbin::detail {

// ============================================================================
// Types.
// ============================================================================

static constexpr uint8_t username_len = 6;
static constexpr uint8_t password_len = 10;
static constexpr uint8_t session_id_len = 10;
static constexpr uint8_t sequence_num_len = 20;

enum message_type : uint8_t {
    mt_debug = '+',
    mt_unsequenced = 'U',

    mt_server_heartbeat = 'H',
    mt_login_accepted = 'A',
    mt_login_rejected = 'J',
    mt_sequenced = 'S',
    mt_end_of_session = 'Z',

    mt_client_heartbeat = 'R',
    mt_login_request = 'L',
    mt_logout_request = 'O',
};

enum reject_code : uint8_t {
    rej_not_authenticated = 'A',
    rej_no_session = 'S',
};

// ============================================================================
// Messages.
// ============================================================================
// NOLINTBEGIN(*-c-arrays)

struct __attribute__((packed)) msg_header {
    uint16_t length;
    message_type type;
};

struct __attribute__((packed)) msg_login_request {
    msg_header hdr;
    char username[username_len];
    char password[password_len];
    char session_id[session_id_len];
    char sequence_num[sequence_num_len];
};

struct __attribute__((packed)) msg_login_accepted {
    msg_header hdr;
    char session_id[session_id_len];
    char sequence_num[sequence_num_len];

    [[nodiscard]] static msg_login_accepted build(std::string_view session_id, std::string_view sequence_num) {
        DEBUG_ASSERT(session_id.length() == session_id_len);
        DEBUG_ASSERT(sequence_num.length() == sequence_num_len);

        msg_login_accepted msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_login_accepted;
        std::memcpy(msg.session_id, session_id.data(), session_id_len);
        std::memcpy(msg.sequence_num, sequence_num.data(), sequence_num_len);

        return msg;
    }
};

struct __attribute__((packed)) msg_login_rejected {
    msg_header hdr;
    reject_code reason;

    static const msg_login_rejected prebuilt_auth;
    static const msg_login_rejected prebuilt_session;
};

struct __attribute__((packed)) msg_server_heartbeat {
    msg_header hdr;

    static const msg_server_heartbeat prebuilt;
};

constexpr size_t msg_minimum_size = sizeof(msg_header);

// NOLINTEND(*-c-arrays)
// ============================================================================
// Formatting.
// ============================================================================

[[nodiscard]] inline std::string_view view_right_padded(const char *field, size_t len) {
    DEBUG_ASSERT(field != nullptr);

    auto view = std::string_view(field, len);
    auto end = view.find_last_not_of(' ');

    if (end == std::string_view::npos) {
        return std::string_view{};
    }

    return view.substr(0, end + 1);
}

[[nodiscard]] inline std::string_view view_left_padded(const char *field, size_t len) {
    DEBUG_ASSERT(field != nullptr);

    auto view = std::string_view(field, len);
    size_t start = view.find_first_not_of(' ');

    if (start == std::string_view::npos) {
        return std::string_view{};
    }

    return view.substr(start);
}

} // namespace soupbin::detail
