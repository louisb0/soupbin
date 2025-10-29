#pragma once

#include "common/assert.hpp"

#include <cstdint>
#include <cstring>
#include <string_view>

#include <arpa/inet.h>
#include <netinet/in.h>

// TODO: alignment
namespace soupbin::common {

// ============================================================================
// Formatting.
// ============================================================================
inline void pad_field_left(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, (dst + width) - src.size());
}

inline void pad_field_right(char *dst, size_t width, std::string_view src) {
    ASSERT(src.size() <= width);

    std::fill_n(dst, width, ' ');
    std::ranges::copy(src, dst);
}

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

// ============================================================================
// Types.
// ============================================================================

static constexpr uint8_t msg_username_len = 6;
static constexpr uint8_t msg_password_len = 10;
static constexpr uint8_t msg_session_id_len = 10;
static constexpr uint8_t msg_sequence_num_len = 20;

enum msg_type : uint8_t {
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

enum msg_reject_code : uint8_t {
    rej_not_authenticated = 'A',
    rej_no_session = 'S',
};

// ============================================================================
// Messages.
// ============================================================================
// NOLINTBEGIN(*-c-arrays)

struct __attribute__((packed)) msg_header {
    uint16_t length;
    msg_type type;
};

struct __attribute__((packed)) msg_login_request {
    msg_header hdr;
    char username[msg_username_len];
    char password[msg_password_len];
    char session_id[msg_session_id_len];
    char sequence_num[msg_sequence_num_len];

    [[nodiscard]] static msg_login_request build(std::string_view username, std::string_view password,
                                                 std::string_view session_id, std::string_view sequence_num) {
        DEBUG_ASSERT(!username.empty());
        DEBUG_ASSERT(username.length() <= msg_username_len);
        DEBUG_ASSERT(!password.empty());
        DEBUG_ASSERT(password.length() <= msg_password_len);
        DEBUG_ASSERT(!session_id.empty());
        DEBUG_ASSERT(session_id.length() <= msg_session_id_len);
        DEBUG_ASSERT(!sequence_num.empty());
        DEBUG_ASSERT(sequence_num.length() <= msg_sequence_num_len);

        msg_login_request msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_login_request;

        // NOLINTBEGIN(bugprone-suspicious-stringview-data-usage)
        pad_field_right(msg.username, msg_username_len, username.data());
        pad_field_right(msg.password, msg_password_len, password.data());
        pad_field_left(msg.session_id, msg_session_id_len, session_id.data());
        pad_field_left(msg.sequence_num, msg_sequence_num_len, sequence_num.data());
        // NOLINTEND(bugprone-suspicious-stringview-data-usage)

        return msg;
    }
};

struct __attribute__((packed)) msg_login_accepted {
    msg_header hdr;
    char session_id[msg_session_id_len];
    char sequence_num[msg_sequence_num_len];

    [[nodiscard]] static msg_login_accepted build(std::string_view session_id, std::string_view sequence_num) {
        DEBUG_ASSERT(session_id.length() == msg_session_id_len);
        DEBUG_ASSERT(sequence_num.length() == msg_sequence_num_len);

        msg_login_accepted msg{};
        msg.hdr.length = htons(sizeof(msg) - sizeof(msg.hdr));
        msg.hdr.type = mt_login_accepted;
        std::memcpy(msg.session_id, session_id.data(), msg_session_id_len);
        std::memcpy(msg.sequence_num, sequence_num.data(), msg_sequence_num_len);

        return msg;
    }
};

struct __attribute__((packed)) msg_login_rejected {
    msg_header hdr;
    msg_reject_code reason;

    static const msg_login_rejected prebuilt_auth;
    static const msg_login_rejected prebuilt_session;
};

struct __attribute__((packed)) msg_server_heartbeat {
    msg_header hdr;

    static const msg_server_heartbeat prebuilt;
};

constexpr size_t msg_minimum_size = sizeof(msg_header);

// NOLINTEND(*-c-arrays)

} // namespace soupbin::common
