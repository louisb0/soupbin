#pragma once

#include <cstdint>

namespace soupbin::detail {

// -------------- types --------------

static constexpr uint8_t username_len = 6;
static constexpr uint8_t password_len = 10;
static constexpr uint8_t session_id_len = 10;
static constexpr uint8_t sequence_num_len = 20;

enum message_type : uint8_t {
    // server <-> client
    mt_debug = '+',
    mt_unsequenced = 'U',

    // server -> client
    mt_login_accepted = 'A',
    mt_login_rejected = 'J',
    mt_sequenced = 'S',
    mt_server_heartbeat = 'H',
    mt_end_of_session = 'Z',

    // client -> server
    mt_login_request = 'L',
    mt_logout_request = 'O',
    mt_client_heartbeat = 'R',
};

enum login_reject_code : uint8_t {
    rej_not_authenticated = 'A',
    rej_no_session = 'S',
};

// -------------- messages --------------
// NOLINTBEGIN(*-c-arrays)

struct __attribute__((packed)) msg_header {
    uint16_t length;
    message_type type;
};

// NOLINTEND(*-c-arrays)

} // namespace soupbin::detail
