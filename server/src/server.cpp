#include "soupbin/server.hpp"

#include "soupbin/errors.hpp"

#include "detail/client_manager.hpp"
#include "detail/config.hpp"
#include "detail/messages.hpp"
#include "detail/network.hpp"
#include "detail/partial.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/util.hpp"

#include "server.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

// TODO:
//  - Revisit logs, transition to structured (https://github.com/gabime/spdlog/issues/1797).
//  - Reconsider value of strong types (e.g. client_count_t, seq_num_t).
//  - Rework pre-commit / devenv.

namespace soupbin {

// ============================================================================
// Declarations.
// ============================================================================

server::server(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
server::server(server &&other) noexcept = default;
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

void server::run() noexcept { impl_->run(); }

// ============================================================================
// Definitions.
// ============================================================================

server::impl::impl(detail::valid_fd_t listener, detail::valid_fd_t epoll, server_config &&cfg) noexcept
    : cmgr_(epoll, listener), cfg_(std::move(cfg)) {}

void server::impl::run() noexcept {
    while (true) {
        detail::cm_batch_context ctx = cmgr_.poll(std::chrono::milliseconds(detail::poll_ms));

        batch_unauthed(ctx);
        batch_authed(ctx);

        for (const auto *client : ctx.all()) {
            if (client->authed()) {
                client->session->catchup(ctx);
            }
        }

        cmgr_.process(ctx);
        cmgr_.onboard(detail::client_count_t{ detail::max_pb_new_clients });

        assert_consistency();
    }
}

void server::impl::batch_unauthed(detail::cm_batch_context &ctx) noexcept {
    const auto unauthed = ctx.unauthed();
    if (unauthed.empty()) {
        return;
    }

    DEBUG_ASSERT(unauthed.size() <= detail::batch_size);
    DEBUG_ASSERT(std::ranges::all_of(unauthed, [](const auto *cl) { return !cl->authed(); }));
    DEBUG_ASSERT(std::ranges::all_of(unauthed, [&ctx](const auto *cl) { return !ctx.dropped(cl->descriptor.handle); }));

    for (auto *client : unauthed) {
        // ----------------------------------------
        // (1) Receive login message.
        // ----------------------------------------
        std::array<std::byte, sizeof(detail::msg_login_request)> login_req_buf{};

        size_t read = client->partial.load(login_req_buf.data());
        if (auto err = detail::recv_all(client->descriptor, login_req_buf.data(), login_req_buf.size(), read)) {
            ctx.mark_drop(client->descriptor.handle, *err);
        }

        if (read != login_req_buf.size()) {
            client->partial.store(login_req_buf.data(), read);
            continue;
        }

        // ----------------------------------------
        // (2) Validate message structure.
        // ----------------------------------------
        const auto *request = reinterpret_cast<const detail::msg_login_request *>(login_req_buf.data());

        if (request->hdr.type != detail::mt_login_request) {
            ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_malformed_message);

            FUZZ_UNREACHABLE();
            continue;
        }

        if (ntohs(request->hdr.length) != sizeof(detail::msg_login_request) - sizeof(detail::msg_header)) {
            ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_malformed_length);

            FUZZ_UNREACHABLE();
            continue;
        }

        // ----------------------------------------
        // (3) Authenticate.
        // ----------------------------------------
        const auto username = detail::view_right_padded(request->username, detail::username_len);
        const auto password = detail::view_right_padded(request->password, detail::password_len);
        if (!cfg_.on_auth(username, password)) {
            static const auto *buf = reinterpret_cast<const std::byte *>(&detail::msg_login_rejected::prebuilt_auth);
            (void)detail::send_all(client->descriptor, buf, sizeof(detail::msg_login_rejected::prebuilt_auth));
            ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::bad_credentials);

            continue;
        }

        // ----------------------------------------
        // (4) Create or authorise against session.
        // ----------------------------------------
        const auto req_sequence_num = detail::view_left_padded(request->sequence_num, detail::sequence_num_len);
        if (req_sequence_num.empty() || !std::ranges::all_of(req_sequence_num, ::isdigit)) {
            ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_malformed_seqnum);

            FUZZ_UNREACHABLE();
            continue;
        }
        const auto sequence_num = detail::seq_num_t{ std::stoul(std::string(req_sequence_num)) };

        const auto req_session_id = detail::view_left_padded(request->session_id, detail::session_id_len);
        const auto session_id =
            req_session_id.empty() ? generate_alphanumeric(detail::session_id_len) : std::string(req_session_id);

        auto [it, inserted] = sessions_.try_emplace(session_id, session_id, std::string(username));
        auto &session = it->second;

        const bool is_existing_session = !inserted;
        const bool is_authorised = session.owned_by(username) && (sequence_num <= session.message_count());
        if (is_existing_session && !is_authorised) {
            static const auto *buf = reinterpret_cast<const std::byte *>(&detail::msg_login_rejected::prebuilt_session);
            (void)detail::send_all(client->descriptor, buf, sizeof(detail::msg_login_rejected));
            ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::bad_session);

            continue;
        }

        // ----------------------------------------
        // (5) Send login accepted, subscribe to session.
        // ----------------------------------------
        const auto accept =
            detail::msg_login_accepted::build(session_id, std::string_view(request->sequence_num, detail::sequence_num_len));
        const auto *accept_buf = reinterpret_cast<const std::byte *>(&accept);

        if (auto err = detail::send_all(client->descriptor, accept_buf, sizeof(accept))) {
            ctx.mark_drop(client->descriptor.handle, *err);
            continue;
        }

        ctx.mark_sent(client->descriptor.handle);
        session.subscribe(*client, sequence_num);

        LOG_INFO("client={} authenticated with session_id={}.", client->descriptor.handle, session_id);
    }
}

void server::impl::batch_authed(detail::cm_batch_context &ctx) const noexcept {
    const auto authed = ctx.authed();
    if (authed.empty()) {
        return;
    }

    DEBUG_ASSERT(authed.size() <= detail::batch_size);
    DEBUG_ASSERT(std::ranges::all_of(authed, [](const auto *cl) { return cl->authed(); }));

    alignas(detail::cache_line_size) std::array<std::byte, detail::max_pb_total_recv> recv_buf{};

    alignas(detail::cache_line_size) std::array<message_view, detail::max_pb_total_num_data_msg> message_views{};
    alignas(detail::cache_line_size) std::array<uint16_t, detail::batch_size> message_view_counts{};
    static_assert(std::numeric_limits<decltype(message_view_counts)::value_type>::max() >=
                  detail::max_pb_client_num_data_msg);

    // ----------------------------------------
    // (1) Receive data, build message views.
    // ----------------------------------------
    size_t recv_buf_offset = 0;
    size_t total_view_count = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        auto *client = authed[i];
        auto *client_buf = recv_buf.data() + recv_buf_offset;

        // 1.1 Receive.
        size_t read = client->partial.load(client_buf);
        if (auto err = detail::recv_all(client->descriptor, client_buf, detail::max_pb_client_recv, read)) {
            ctx.mark_drop(client->descriptor.handle, *err);

            if (read < detail::msg_minimum_size) {
                continue;
            }
        }

        // 1.2 Build message views.
        size_t parsed = 0;
        while (parsed != read) {
            const size_t available = read - parsed;
            if (available < sizeof(detail::msg_header)) {
                break;
            }

            const auto *header = reinterpret_cast<const detail::msg_header *>(client_buf + parsed);
            const size_t payload_length = ntohs(header->length);
            if (payload_length > detail::max_payload_size) {
                ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_excessive_length);

                FUZZ_UNREACHABLE();
                continue;
            }

            const size_t message_length = sizeof(detail::msg_header) + payload_length;
            if (available < message_length) {
                break;
            }

            switch (header->type) {
            case detail::mt_debug:
            case detail::mt_unsequenced: {
                static_assert(std::is_same_v<decltype(detail::max_payload_size), const uint8_t>);

                const auto *payload_start = reinterpret_cast<const std::byte *>(header) + sizeof(detail::msg_header);
                const auto payload_size = static_cast<uint8_t>(payload_length);
                const auto message_type =
                    (header->type == detail::mt_debug) ? message_type::debug : message_type::unsequenced;

                message_views[total_view_count++] = { .offset = payload_start, .len = payload_size, .type = message_type };
                message_view_counts[i]++;

                DEBUG_ASSERT(total_view_count <= message_views.size());
                DEBUG_ASSERT(message_view_counts[i] <= detail::max_pb_client_num_data_msg);
                break;
            }

            case detail::mt_logout_request: {
                ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::orderly_logout);

                break;
            }

            case detail::mt_client_heartbeat: {
                break;
            }

            case detail::mt_login_accepted:
            case detail::mt_login_rejected:
            case detail::mt_sequenced:
            case detail::mt_server_heartbeat:
            case detail::mt_end_of_session:
            case detail::mt_login_request: {
                ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_unexpected_type);

                FUZZ_UNREACHABLE();
                break;
            }

            default: {
                ctx.mark_drop(client->descriptor.handle, detail::cm_batch_context::drop_reason::proto_malformed_type);

                FUZZ_UNREACHABLE();
                break;
            }
            }

            DEBUG_ASSERT(parsed + message_length <= read);
            parsed += message_length;
        }

        client->partial.store(client_buf + parsed, read - parsed);

        // 1.3 Advance.
        DEBUG_ASSERT(recv_buf_offset + parsed <= recv_buf.size());
        recv_buf_offset += parsed;
    }
#ifndef NDEBUG
    for (const auto &msg : std::span(message_views.begin(), total_view_count)) {
        DEBUG_ASSERT(msg.type == message_type::debug || msg.type == message_type::unsequenced);
        DEBUG_ASSERT(msg.len <= detail::max_payload_size);
    }
#endif

    // ----------------------------------------
    // (2) Return message views to user layer.
    // ----------------------------------------
    size_t message_view_offset = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        const auto *client = authed[i];
        const auto client_view_count = message_view_counts[i];

        if (client_view_count == 0) {
            continue;
        }

        // 2.2 Run callback and buffer responses.
        alignas(detail::cache_line_size) std::array<std::byte, detail::max_pb_client_send> reply_buf{};
        size_t reply_buf_offset = 0;

        // clang-format off
        auto handle_reply = [&reply_buf, &reply_buf_offset, &ctx, client](
            message_type type,
            std::span<const std::byte> payload
        ) -> std::error_code {
            if (payload.empty()) {
                return make_soupbin_error(errc::reply_too_small);
            }

            if (payload.size() > detail::max_payload_size) {
                return make_soupbin_error(errc::reply_too_large);
            }

            if (type == message_type::sequenced) {
                client->session->append_seq_msg(payload);
            } else {
                DEBUG_ASSERT(type == message_type::debug || type == message_type::unsequenced);

                const size_t total_message_size = sizeof(detail::msg_header) + payload.size();
                DEBUG_ASSERT(reply_buf_offset + total_message_size <= reply_buf.size());

                const size_t header_offset = reply_buf_offset;
                auto *header = reinterpret_cast<detail::msg_header *>(reply_buf.data() + header_offset);
                header->length = htons(static_cast<uint16_t>(payload.size()));
                header->type = (type == message_type::debug) ? detail::mt_debug : detail::mt_unsequenced;

                const size_t payload_offset = header_offset + sizeof(detail::msg_header);
                std::memcpy(reply_buf.data() + payload_offset, payload.data(), payload.size());

                reply_buf_offset += total_message_size;
            }

            ctx.mark_sent(client->descriptor.handle);
            return std::error_code{};
        };
        // clang-format on

        const auto session_id = std::string_view(client->session->id());
        const auto client_messages = std::span{ &message_views[message_view_offset], client_view_count };

        cfg_.on_client_messages(session_id, client_messages, handle_reply);

        // 2.3 Send buffered non-sequenced data.
        if (auto err = detail::send_all(client->descriptor, reply_buf.data(), reply_buf_offset)) {
            ctx.mark_drop(client->descriptor.handle, *err);
        }

        message_view_offset += client_view_count;

#ifndef NDEBUG
        size_t parsed = 0;
        while (parsed != reply_buf_offset) {
            const size_t available = reply_buf_offset - parsed;
            DEBUG_ASSERT(available >= sizeof(detail::msg_header));

            const auto *header = reinterpret_cast<const detail::msg_header *>(reply_buf.data() + parsed);
            DEBUG_ASSERT(header->type == detail::mt_debug || header->type == detail::mt_unsequenced);

            const size_t payload_length = ntohs(header->length);
            DEBUG_ASSERT(payload_length > 0);
            DEBUG_ASSERT(payload_length <= detail::max_payload_size);

            const size_t message_length = sizeof(detail::msg_header) + payload_length;
            DEBUG_ASSERT(available >= message_length);

            DEBUG_ASSERT(parsed + message_length <= reply_buf_offset);
            parsed += message_length;
        }
#endif
    }
    DEBUG_ASSERT(message_view_offset == total_view_count);
}

void server::impl::assert_consistency() const noexcept {
#ifndef NDEBUG
    // ----------------------------------------
    // (1) Within stores.
    // ----------------------------------------
    const std::vector<detail::cl_random_access> &all_clients = cmgr_.assert_consistency();
    std::unordered_set<detail::cl_descriptor> all_subscribers;

    for (const auto &[session_id, session] : sessions_) {
        DEBUG_ASSERT(session_id == session.id());

        auto subscribers = session.assert_consistency();
        for (const auto &sub : subscribers) {
            DEBUG_ASSERT(!all_subscribers.contains(sub));
        }

        all_subscribers.merge(std::move(subscribers));
    }

    // ----------------------------------------
    // (2) Across stores.
    // ----------------------------------------
    std::unordered_set<detail::cl_descriptor> authed_clients;
    for (const auto &client : all_clients) {
        if (client.authed()) {
            const auto [_, inserted] = authed_clients.insert(client.descriptor);
            DEBUG_ASSERT(inserted);
        }
    }

    // NOTE: Ensures each subscriber maps to exactly one authenticated client.
    for (const auto &sub : all_subscribers) {
        DEBUG_ASSERT(authed_clients.erase(sub) == 1);
    }
    DEBUG_ASSERT(authed_clients.empty());
#endif
}

// ============================================================================
// Factory.
// ============================================================================

std::expected<server, std::error_code> make_server(server_config cfg) {
    if (cfg.hostname.empty()) {
        return std::unexpected(make_soupbin_error(errc::setup_hostname_format));
    }

    if (cfg.port.empty()) {
        return std::unexpected(make_soupbin_error(errc::setup_port_format));
    }

    // Resolve address.
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res{};
    int gai_c = getaddrinfo(cfg.hostname.c_str(), cfg.port.c_str(), &hints, &res);
    if (gai_c != 0) {
        const char *err = (gai_c == EAI_SYSTEM) ? std::strerror(errno) : gai_strerror(gai_c);
        LOG_CRITICAL("getaddrinfo() failed (likely due to user error): {}.", err);

        if (gai_c == EAI_SYSTEM) {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }
        return std::unexpected(make_gai_error(gai_c));
    }

    // Find a suitable binding address.
    int listener_fd = -1;
    for (addrinfo *it = res; it != nullptr; it = it->ai_next) {
        int fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd == -1) {
            continue;
        }

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            close(fd);
            continue;
        }

        if (bind(fd, it->ai_addr, it->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        if (listen(fd, SOMAXCONN) == -1) {
            close(fd);
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            continue;
        }

        listener_fd = fd;
        break;
    }

    freeaddrinfo(res);

    if (listener_fd == -1) {
        return std::unexpected(make_soupbin_error(errc::setup_not_listenable));
    }

    // Create epoll instance and server.
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG_CRITICAL("epoll_create1() failed unexpectedly: {}.", std::strerror(errno));

        int saved_errno = errno;
        close(listener_fd);
        return std::unexpected(std::error_code(saved_errno, std::system_category()));
    }

    return server(
        std::make_unique<server::impl>(detail::valid_fd_t(listener_fd), detail::valid_fd_t(epoll_fd), std::move(cfg)));
}

} // namespace soupbin
