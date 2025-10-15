#include "messages.hpp"

namespace soupbin::detail {

const msg_server_heartbeat msg_server_heartbeat::prebuilt = {
    .hdr = { .length = htons(0), .type = mt_server_heartbeat },
};

const msg_login_rejected msg_login_rejected::prebuilt_auth = {
    .hdr = { .length = htons(sizeof(rej_not_authenticated)), .type = mt_login_rejected },
    .reason = rej_not_authenticated,
};

const msg_login_rejected msg_login_rejected::prebuilt_session = {
    .hdr = { .length = htons(sizeof(rej_not_authenticated)), .type = mt_login_rejected },
    .reason = rej_no_session,
};

} // namespace soupbin::detail
