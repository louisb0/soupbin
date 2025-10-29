
#include "soupbin/client.hpp"

#include "soupbin/errors.hpp"

#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include "common/messages.hpp"
#include "common/util.hpp"

#include "client.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>
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
// Declarations.
// ============================================================================

client::client(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
client::client(client &&other) noexcept = default;
client &client::operator=(client &&) noexcept = default;
client::~client() noexcept = default;

void client::send(message_type type, std::span<const std::byte> payload) noexcept { impl_->send(type, payload); }
void client::recv(message_type &type, std::span<std::byte> buffer) noexcept { impl_->recv(type, buffer); }
bool client::try_send(message_type type, std::span<const std::byte> payload) noexcept {
    return impl_->try_send(type, payload);
}
bool client::try_recv(message_type &type, std::span<std::byte> buffer) noexcept { return impl_->try_recv(type, buffer); }

bool client::disconnect() noexcept { return impl_->disconnect(); }
bool client::connected() const noexcept { return impl_->connected(); }

const std::string &client::session_id() const noexcept { return impl_->session_id(); }
size_t client::sequence_num() const noexcept { return impl_->sequence_num(); }

// ============================================================================
// Definitons.
// ============================================================================
client::impl::impl(std::unique_ptr<detail::ev_loop> loop, std::string session_id, common::seq_num_t sequence_num)
    : loop_(std::move(loop)), session_id_(std::move(session_id)), sequence_num_(sequence_num) {
    ASSERT(session_id_.length() == common::msg_session_id_len);
    ASSERT(loop_->thread().joinable());
}

void client::impl::send(message_type type, std::span<const std::byte> payload) noexcept {}
void client::impl::recv(message_type &type, std::span<std::byte> buffer) noexcept {}

bool client::impl::try_send(message_type type, std::span<const std::byte> payload) noexcept { return false; }
bool client::impl::try_recv(message_type &type, std::span<std::byte> buffer) noexcept { return false; }

bool client::impl::disconnect() noexcept { return true; }
bool client::impl::connected() const noexcept { return true; }

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

        auto send_queue = detail::spsc_ringbuf::create(common::page_size);
        if (!send_queue) {
            LOG_CRITICAL("failed to create send queue.", std::strerror(errno));
            common::preserving_close(cfd);
            return std::unexpected(send_queue.error());
        }

        auto recv_queue = detail::spsc_ringbuf::create(common::page_size);
        if (!recv_queue) {
            LOG_CRITICAL("failed to create recv queue.", std::strerror(errno));
            common::preserving_close(cfd);
            return std::unexpected(recv_queue.error());
        }

        auto ev_loop =
            std::make_unique<detail::ev_loop>(common::valid_fd_t(cfd), std::move(*send_queue), std::move(*recv_queue));

        try {
            ev_loop->start_thread();
        } catch (const std::system_error &e) {
            LOG_CRITICAL("failed to start event loop thread.", std::strerror(errno));
            common::preserving_close(cfd);
            return std::unexpected(e.code());
        }

        return client(std::make_unique<impl>(std::move(ev_loop), session_id, common::seq_num_t(std::stoul(sequence_num))));
    }

    default:
        common::preserving_close(cfd);
        FUZZ_UNREACHABLE();
        return std::unexpected(make_soupbin_error(errc::protocol));
    }
}

} // namespace soupbin
