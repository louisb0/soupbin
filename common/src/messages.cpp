#include "common/messages.hpp"

namespace soupbin::common {

const msg_login_rejected msg_login_rejected::prebuilt_auth = {
    .hdr = { .length = htons(sizeof(rej_not_authenticated)), .type = mt_login_rejected },
    .reason = rej_not_authenticated,
};

const msg_login_rejected msg_login_rejected::prebuilt_session = {
    .hdr = { .length = htons(sizeof(rej_not_authenticated)), .type = mt_login_rejected },
    .reason = rej_no_session,
};

const msg_logout_request msg_logout_request::prebuilt = {
    .hdr = { .length = htons(0), .type = mt_logout_request },
};

const msg_server_heartbeat msg_server_heartbeat::prebuilt = {
    .hdr = { .length = htons(0), .type = mt_server_heartbeat },
};

const msg_client_heartbeat msg_client_heartbeat::prebuilt = {
    .hdr = { .length = htons(0), .type = mt_client_heartbeat },
};

} // namespace soupbin::common
