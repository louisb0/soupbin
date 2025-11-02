#include "client_impl.hpp"

#include "soupbin/client.hpp"
#include "soupbin/errors.hpp"

#include "detail/config.hpp"
#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include "common/messages.hpp"
#include "common/util.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <system_error>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace soupbin {

// ============================================================================
// Forwarding.
// ============================================================================
client::client(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
client::client(client &&other) noexcept = default;
client &client::operator=(client &&) noexcept = default;
client::~client() noexcept = default;

client::impl::impl(std::unique_ptr<detail::ev_loop> loop, std::string session_id, common::seq_num_t sequence_num) noexcept
    : event_loop_(std::move(loop)), session_id_(std::move(session_id)), sequence_num_(sequence_num) {
    ASSERT(event_loop_->thread().joinable());
    ASSERT(session_id_.length() == common::msg_session_id_len);
}

std::error_code client::send(message_type type, std::span<const std::byte> payload) noexcept {
    return impl_
        ->send_impl(type, payload,
                    [](detail::spsc_ringbuf &queue, size_t bytes) {
                        auto *position = queue.write_prepare(bytes);
                        DEBUG_ASSERT(position != nullptr);
                        return position;
                    })
        .value();
}

std::error_code client::recv(message_type &type, std::span<std::byte> buffer, size_t &bytes) noexcept {
    return impl_
        ->recv_impl(type, buffer, bytes,
                    [](detail::spsc_ringbuf &queue) {
                        auto slot = queue.read_prepare();
                        DEBUG_ASSERT(!slot.empty());
                        DEBUG_ASSERT(slot.size() > sizeof(common::msg_header));
                        return slot;
                    })
        .value();
}

std::optional<std::error_code> client::try_send(message_type type, std::span<const std::byte> payload) noexcept {
    return impl_->send_impl(type, payload,
                            [](detail::spsc_ringbuf &queue, size_t bytes) { return queue.write_try_prepare(bytes); });
}

std::optional<std::error_code> client::try_recv(message_type &type, std::span<std::byte> buffer, size_t &bytes) noexcept {
    return impl_->recv_impl(type, buffer, bytes, [](detail::spsc_ringbuf &queue) { return queue.read_try_prepare(); });
}

void client::disconnect() noexcept { impl_->event_loop_->thread().request_stop(); }
bool client::connected() const noexcept { return impl_->event_loop_->connected(); }
enum disconnect_reason client::disconnect_reason() const noexcept { return impl_->event_loop_->disconnect_reason(); }

const std::string &client::session_id() const noexcept { return impl_->session_id_; }
size_t client::sequence_num() const noexcept { return common::ts::get(impl_->sequence_num_); }

// ============================================================================
// Implementation.
// ============================================================================
template <typename AcquirePosition>
std::optional<std::error_code> client::impl::send_impl(message_type type, std::span<const std::byte> payload,
                                                       AcquirePosition acq_pos) {
    // ----------------------------------------
    // (1) Validate.
    // ----------------------------------------
    if (!event_loop_->connected()) {
        return make_soupbin_error(errc::disconnected);
    }

    if (type == message_type::none || type == message_type::sequenced) {
        return make_soupbin_error(errc::invalid_message_type);
    }

    if (payload.empty()) {
        return make_soupbin_error(errc::payload_too_small);
    }

    if (payload.size() > common::max_payload_size) {
        return make_soupbin_error(errc::payload_too_large);
    }

    DEBUG_ASSERT(type == message_type::unsequenced || type == message_type::debug);

    // ----------------------------------------
    // (2) Acquire, write, commit.
    // ----------------------------------------
    const size_t message_size = sizeof(common::msg_header) + payload.size();
    auto *position = acq_pos(event_loop_->send_rb(), message_size);
    if (position == nullptr) {
        return std::nullopt;
    }

    auto *header = reinterpret_cast<common::msg_header *>(position);
    header->length = htons(payload.size());
    header->type = (type == message_type::unsequenced) ? common::mt_unsequenced : common::mt_debug;
    std::memcpy(position + sizeof(*header), payload.data(), payload.size());

    event_loop_->send_rb().write_commit(message_size);
    return {};
}

template <typename AcquireSlot>
std::optional<std::error_code> client::impl::recv_impl(message_type &type, std::span<std::byte> buffer, size_t &bytes,
                                                       AcquireSlot acq_slot) {
    // ----------------------------------------
    // (1) Validate.
    // ----------------------------------------
    if (!event_loop_->connected()) {
        return make_soupbin_error(errc::disconnected);
    }

    if (buffer.size() < common::max_payload_size) {
        return make_soupbin_error(errc::buffer_too_small);
    }

    // ----------------------------------------
    // (2) Acquire, read, commit.
    // ----------------------------------------
    auto slot = acq_slot(event_loop_->recv_rb());
    if (slot.empty()) {
        return std::nullopt;
    }

    const auto *header = reinterpret_cast<const common::msg_header *>(slot.data());
    const size_t payload_size = ntohs(header->length);
    const size_t message_size = sizeof(common::msg_header) + payload_size;

    DEBUG_ASSERT(payload_size <= common::max_payload_size);
    DEBUG_ASSERT(slot.size() >= message_size);

    switch (header->type) {
    case common::mt_debug:
        type = message_type::debug;
        break;
    case common::mt_unsequenced:
        type = message_type::unsequenced;
        break;
    case common::mt_sequenced:
        type = message_type::sequenced;
        sequence_num_++;
        break;

    case common::mt_server_heartbeat:
    case common::mt_login_accepted:
    case common::mt_login_rejected:
    case common::mt_end_of_session:
    case common::mt_client_heartbeat:
    case common::mt_login_request:
    case common::mt_logout_request:
        ASSERT_UNREACHABLE();
        break;
    }
    std::memcpy(buffer.data(), slot.data() + sizeof(*header), payload_size);
    bytes = payload_size;

    event_loop_->recv_rb().read_commit(message_size);
    return {};
}

// ============================================================================
// Factory.
// ============================================================================
std::expected<client, std::error_code> client::connect(const connect_config &cfg) noexcept {
    // ----------------------------------------
    // (1) Validate.
    // ----------------------------------------
    if (cfg.hostname.empty()) {
        return std::unexpected(make_soupbin_error(errc::setup_hostname_format));
    }

    if (cfg.port.empty()) {
        return std::unexpected(make_soupbin_error(errc::setup_port_format));
    }

    if (cfg.username.empty() || cfg.username.length() > common::msg_username_len) {
        return std::unexpected(make_soupbin_error(errc::setup_username_format));
    }

    if (cfg.password.empty() || cfg.password.length() > common::msg_password_len) {
        return std::unexpected(make_soupbin_error(errc::setup_password_format));
    }

    if (cfg.session_id.empty() || cfg.session_id.length() > common::msg_session_id_len) {
        return std::unexpected(make_soupbin_error(errc::setup_session_id_format));
    }

    if (cfg.sequence_num.empty() || cfg.sequence_num.length() > common::msg_sequence_num_len) {
        return std::unexpected(make_soupbin_error(errc::setup_sequence_num_format));
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res{};
    int gai_c = getaddrinfo(cfg.hostname.c_str(), cfg.port.c_str(), &hints, &res);
    if (gai_c != 0) {
        LOG_CRITICAL("failed to resolve address.");

        if (gai_c == EAI_SYSTEM) {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }

        return std::unexpected(make_gai_error(gai_c));
    }

    // ----------------------------------------
    // (2) Connect.
    // ----------------------------------------
    int cfd = -1;
    for (addrinfo *it = res; it != nullptr; it = it->ai_next) {
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == -1) {
            continue;
        }

        if (::connect(fd, it->ai_addr, it->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        cfd = fd;
        break;
    }
    freeaddrinfo(res);

    if (cfd == -1) {
        return std::unexpected(make_soupbin_error(errc::setup_not_connectable));
    }

    // ----------------------------------------
    // (3) Request login and parse reply.
    // ----------------------------------------
    const auto request = common::msg_login_request::build(cfg.username, cfg.password, cfg.session_id, cfg.sequence_num);
    if (::send(cfd, &request, sizeof(request), 0) == -1) {
        LOG_CRITICAL("failed to send() login request.");
        common::preserving_close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    static_assert(sizeof(common::msg_login_accepted) >= sizeof(common::msg_login_rejected));
    std::array<std::byte, sizeof(common::msg_login_accepted)> response_buffer{};

    ssize_t header_bytes = ::recv(cfd, response_buffer.data(), sizeof(common::msg_header), MSG_WAITALL);
    if (header_bytes != sizeof(common::msg_header)) {
        LOG_CRITICAL("failed to recv() login response header.");
        common::preserving_close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    const auto *header = reinterpret_cast<const common::msg_header *>(response_buffer.data());
    const size_t payload_size = ntohs(header->length);

    ssize_t payload_bytes = ::recv(cfd, response_buffer.data() + sizeof(common::msg_header), payload_size, MSG_WAITALL);
    if (payload_bytes != static_cast<ssize_t>(payload_size)) {
        LOG_CRITICAL("failed to recv() login response payload.");
        common::preserving_close(cfd);
        return std::unexpected(std::error_code(errno, std::system_category()));
    }

    // ----------------------------------------
    // (4) Process response.
    // ----------------------------------------
    switch (header->type) {
    case common::mt_login_rejected: {
        const auto *reject = reinterpret_cast<const common::msg_login_rejected *>(response_buffer.data());
        common::preserving_close(cfd);

        switch (reject->reason) {
        case common::rej_not_authenticated:
            return std::unexpected(make_soupbin_error(errc::no_such_login));
        case common::rej_no_session:
            return std::unexpected(make_soupbin_error(errc::no_such_session));

        default:
            FUZZ_UNREACHABLE();
            return std::unexpected(make_soupbin_error(errc::protocol));
        }
    }

    case common::mt_login_accepted: {
        const auto *accept = reinterpret_cast<const common::msg_login_accepted *>(response_buffer.data());

        const auto session_id = std::string(common::view_left_padded(accept->session_id, common::msg_session_id_len));
        const auto sequence_num = std::string(common::view_left_padded(accept->sequence_num, common::msg_sequence_num_len));

        DEBUG_ASSERT(cfg.session_id == soupbin::new_session || cfg.session_id == session_id);
        DEBUG_ASSERT(cfg.sequence_num == sequence_num);

        int flags = fcntl(cfd, F_GETFL, 0);
        if (flags == -1 || fcntl(cfd, F_SETFL, flags | O_NONBLOCK) == -1) {
            LOG_CRITICAL("failed to set fd as non-blocking.", std::strerror(errno));
            common::preserving_close(cfd);
            return std::unexpected(std::error_code(errno, std::system_category()));
        }

        auto rb_send = detail::spsc_ringbuf::create(detail::send_queue_size);
        if (!rb_send) {
            LOG_CRITICAL("failed to create send queue.", std::strerror(errno));
            close(cfd);
            return std::unexpected(rb_send.error());
        }

        auto rb_recv = detail::spsc_ringbuf::create(detail::recv_queue_size);
        if (!rb_recv) {
            LOG_CRITICAL("failed to create recv queue.", std::strerror(errno));
            close(cfd);
            return std::unexpected(rb_recv.error());
        }

        auto ev_loop = std::make_unique<detail::ev_loop>(common::valid_fd_t(cfd), std::move(*rb_send), std::move(*rb_recv));

        try {
            ev_loop->start_thread();
        } catch (const std::system_error &e) {
            LOG_CRITICAL("failed to start event loop thread.", std::strerror(errno));
            close(cfd);
            return std::unexpected(e.code());
        }

        return client(std::make_unique<impl>(std::move(ev_loop), session_id, common::seq_num_t(std::stoul(sequence_num))));
    }

    default:
        close(cfd);
        FUZZ_UNREACHABLE();
        return std::unexpected(make_soupbin_error(errc::protocol));
    }
}

} // namespace soupbin
