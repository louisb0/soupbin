#include "soupbin/server.hpp"

#include "soupbin/errors.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"

#include "detail/client_store.hpp"
#include "detail/constants.hpp"
#include "detail/messages.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"
#include "detail/verify.hpp"

#include <algorithm>
#include <array>
#include <bitset>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace soupbin::detail;

namespace soupbin {

// --------------- declaration ---------------

class server::impl {
    valid_fd_t listener_;
    client_store cstore_;
    server_config cfg_;

    std::unordered_map<uint64_t, session> sessions_;

public:
    impl(valid_fd_t listener, valid_fd_t epoll, server_config &&cfg)
        : listener_(listener), cstore_(epoll, client_handle_t{ constants::bound::clients }), cfg_(std::move(cfg)) {
        ASSERT(verify::fd(listener));
        ASSERT(verify::listener(listener));
    }

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;
    ~impl() = default;

    [[nodiscard]] std::error_code run() noexcept;

private:
    using drop_list = std::bitset<constants::bound::clients>;
    using sent_list = std::bitset<constants::bound::clients>;

    void batch_authed(std::span<cl_loop_info *> authed, drop_list &to_drop, sent_list &did_send) const noexcept;
    void batch_unauthed(std::span<cl_loop_info *> unauthed, drop_list &to_drop) noexcept;

    // TODO: Location.
    static bool send_all(const cl_loop_info *client, const std::byte *buf, size_t len) noexcept;
    static bool recv_all(const cl_loop_info *client, std::byte *buf, size_t len, size_t &read) noexcept;
};

server::server(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
server::server(server &&other) noexcept = default;
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

std::error_code server::run() noexcept { return impl_->run(); }

// ---------------- definition ---------------

std::error_code server::impl::run() noexcept {
    while (true) {
        drop_list to_drop;
        sent_list did_send;

        std::span<cl_loop_info *> all;
        {
            auto [authed, unauthed] = cstore_.ready(cfg_.tick_ms);

            batch_authed(authed, to_drop, did_send);
            batch_unauthed(authed, to_drop);

            DEBUG_ASSERT(authed.data() + authed.size() == unauthed.data());
            all = std::span{ authed.data(), authed.size() + unauthed.size() };
        }

        // TODO: Send all queued sequenced data - what about dropped clients?
        // TODO: Set activity.
        // TODO: Heartbeats.
        // TODO: Drop clients.
        // TODO: Accept clients.
    }

    return {};
}

void server::impl::batch_authed(std::span<cl_loop_info *> authed, drop_list &to_drop, sent_list &did_send) const noexcept {
    if (authed.empty()) {
        return;
    }

    DEBUG_ASSERT(authed.size() <= constants::batch::size);
    DEBUG_ASSERT(std::ranges::all_of(authed, [](const auto *client) { return client->authed(); }));

    alignas(constants::cache_line_sz) std::array<std::byte, constants::bound::max_recv> recv_buf{};
    alignas(constants::cache_line_sz) std::array<message_descriptor, constants::bound::max_data_msg> descriptors{};
    alignas(constants::cache_line_sz) std::array<uint8_t, constants::batch::size> client_descriptor_counts{};
    static_assert(std::numeric_limits<decltype(client_descriptor_counts)::value_type>::max() >=
                  constants::batch::client_data_msg);

    // ----------------------------------------
    // (1) Receive data, build descriptors.
    // ----------------------------------------
    size_t recv_buf_offset = 0;
    size_t total_descriptor_count = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        auto *client = authed[i];
        auto *client_buf = recv_buf.data() + recv_buf_offset;

        // 1.1 Receive.
        size_t read = client->partial.load(client_buf);
        bool success = recv_all(client, client_buf, constants::batch::client_recv, read);
        if (!success) {
            to_drop[client->handle.get()] = true;

            if (read == 0) {
                continue;
            }
        }

        // 1.2 Build message descriptors.
        size_t parsed = 0;
        while (parsed != read) {
            const size_t available = read - parsed;
            if (available < sizeof(msg_header)) {
                break;
            }

            const auto *header = reinterpret_cast<const msg_header *>(client_buf + parsed);
            const size_t payload_len = ntohs(header->length);
            if (payload_len > constants::max_payload_size) {
                LOG_WARN("client={} payload too large at {} bytes.", client->fd.get(), payload_len);
                to_drop[client->handle.get()] = true;
                FUZZ_UNREACHABLE();
                break;
            }

            const size_t message_len = sizeof(msg_header) + payload_len;
            if (available < message_len) {
                break;
            }

            switch (header->type) {
            case mt_debug:
            case mt_unsequenced: {
                DEBUG_ASSERT(payload_len <= constants ::max_payload_size);
                static_assert(std::is_same_v<decltype(constants::max_payload_size), const uint8_t>);

                descriptors[total_descriptor_count++] = {
                    .offset = reinterpret_cast<const std::byte *>(header) + sizeof(msg_header),
                    .len = static_cast<uint8_t>(payload_len),
                    .type = (header->type == mt_debug) ? message_type::debug : message_type::unsequenced,
                };
                client_descriptor_counts[i]++;

                DEBUG_ASSERT(total_descriptor_count <= descriptors.size());
                DEBUG_ASSERT(client_descriptor_counts[i] <= constants::batch::client_data_msg);
                break;
            }

            case mt_logout_request: {
                LOG_DEBUG("client={} requested logout.", client->handle.get());
                to_drop[client->handle.get()] = true;
                break;
            }

            case mt_client_heartbeat: {
                break;
            }

            case mt_login_accepted:
            case mt_login_rejected:
            case mt_sequenced:
            case mt_server_heartbeat:
            case mt_end_of_session:
            case mt_login_request: {
                LOG_WARN("client={} sent unexpected mt={}.", client->handle.get(), static_cast<char>(header->type));
                to_drop[client->handle.get()] = true;
                FUZZ_UNREACHABLE();
                break;
            }

            default: {
                LOG_WARN("client={} sent unknown mt={}.", client->handle.get(), static_cast<char>(header->type));
                to_drop[client->handle.get()] = true;
                FUZZ_UNREACHABLE();
                break;
            }
            }

            DEBUG_ASSERT(parsed + message_len <= read);
            parsed += message_len;
        }

        // 1.3 Advance.
        client->partial.store(client_buf + parsed, read - parsed);

        DEBUG_ASSERT(recv_buf_offset + parsed <= recv_buf.size());
        recv_buf_offset += parsed;
    }

    // ----------------------------------------
    // (2) Return descriptors to user-layer.
    // ----------------------------------------
    size_t descriptor_offset = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        const auto *client = authed[i];
        const auto client_descriptor_count = client_descriptor_counts[i];

        // 2.1 Fetch and validate client descriptors.
        if (client_descriptor_count == 0) {
            continue;
        }
        DEBUG_ASSERT(client_descriptor_count <= constants::batch::client_data_msg);

        const std::span<message_descriptor> client_descriptors = {
            &descriptors[descriptor_offset],
            client_descriptor_count,
        };
        for (const auto &msg : client_descriptors) {
            DEBUG_ASSERT(msg.type == message_type::debug || msg.type == message_type::unsequenced);
            DEBUG_ASSERT(msg.len <= constants::max_payload_size);
        }

        // 2.2 Run callback and buffer responses.
        alignas(constants::cache_line_sz) std::array<std::byte, constants::batch::client_data_send> reply_buf{};
        size_t reply_buf_offset = 0;

        cfg_.on_client_msgs(
            std::string_view(client->sess->id()), client_descriptors,
            [&reply_buf, &reply_buf_offset, &did_send, client](message_type type, std::span<const std::byte> payload) {
                if (payload.empty()) {
                    return make_soupbin_error(errc::reply_too_small);
                }
                if (payload.size() > constants::max_payload_size) {
                    return make_soupbin_error(errc::reply_too_large);
                }

                if (type == message_type::sequenced) {
                    client->sess->append_sequenced_msg(payload);
                } else {
                    DEBUG_ASSERT(type == message_type::debug || type == message_type::unsequenced);
                    DEBUG_ASSERT(reply_buf_offset + sizeof(msg_header) + payload.size() <= reply_buf.size());

                    auto *header = reinterpret_cast<msg_header *>(reply_buf.data() + reply_buf_offset);
                    header->length = htons(static_cast<uint16_t>(payload.size()));
                    header->type = (type == message_type::debug) ? mt_debug : mt_unsequenced;
                    std::memcpy(reply_buf.data() + reply_buf_offset + sizeof(msg_header), payload.data(), payload.size());

                    reply_buf_offset += sizeof(msg_header) + payload.size();
                }

                did_send[client->handle.get()] = true;
                return std::error_code{};
            });

        // TODO: Assert validity of reply buffer?
        // TODO: Assert validity of session buffer?

        // 2.3 Send buffered non-sequenced data.
        bool success = send_all(client, reply_buf.data(), reply_buf_offset);
        if (!success) {
            to_drop[client->handle.get()] = true;
        }

        descriptor_offset += client_descriptor_count;
    }
    DEBUG_ASSERT(descriptor_offset == total_descriptor_count);

    LOG_INFO("total_descriptor_count={} data messages were forwarded to the user-layer.", total_descriptor_count);
}

void server::impl::batch_unauthed(std::span<cl_loop_info *> unauthed, drop_list &to_drop) noexcept {
    if (unauthed.empty()) {
        return;
    }

    DEBUG_ASSERT(unauthed.size() <= constants::batch::size);
    DEBUG_ASSERT(std::ranges::all_of(unauthed, [](const auto *client) { return !client->authed(); }));
    DEBUG_ASSERT(std::ranges::all_of(unauthed, [&to_drop](const auto *client) { return !to_drop[client->handle.get()]; }));

    for (auto *client : unauthed) {
        std::array<std::byte, sizeof(msg_login_request)> login_req_buf{};

        // ----------------------------------------
        // (1) Receive login message.
        // ----------------------------------------
        size_t read = client->partial.load(login_req_buf.data());
        bool success = recv_all(client, login_req_buf.data(), login_req_buf.size(), read);
        if (!success) {
            to_drop[client->handle.get()] = true;
            continue;
        }

        if (read != login_req_buf.size()) {
            client->partial.store(login_req_buf.data(), read);
            continue;
        }

        // ----------------------------------------
        // (2) Validate message structure.
        // ----------------------------------------
        const auto *request = reinterpret_cast<const msg_login_request *>(login_req_buf.data());

        if (request->hdr.type != mt_login_request) {
            LOG_WARN("client={} did not send a login request.", client->handle.get());
            to_drop[client->handle.get()] = true;
            FUZZ_UNREACHABLE();
            continue;
        }

        if (request->hdr.length != sizeof(msg_login_request) - sizeof(msg_header)) {
            LOG_WARN("client={} sent a login request with bad length.", client->handle.get());
            to_drop[client->handle.get()] = true;
            FUZZ_UNREACHABLE();
            continue;
        }

        const std::string_view username = view_right_padded(request->username, username_len);
        const std::string_view password = view_right_padded(request->password, password_len);
        const std::string_view req_session_id = view_left_padded(request->session_id, session_id_len);
        const std::string_view sequence_num = view_left_padded(request->sequence_num, sequence_num_len);

        LOG_INFO("client={} requesting login with username='{}' password='{}' session_id='{}' sequence_num={}",
                 client->handle.get(), username, password, req_session_id, sequence_num);

        // ----------------------------------------
        // (3) Validate credentials.
        // ----------------------------------------
        if (!cfg_.on_auth(username, password)) {
            LOG_INFO("client={} failed authentication callback.", client->handle.get());

            const auto reject = msg_login_rejected::build(rej_not_authenticated);
            const auto *reject_buf = reinterpret_cast<const std::byte *>(&reject);
            send_all(client, reject_buf, sizeof(reject));

            to_drop[client->handle.get()] = true;
            continue;
        }

        // ----------------------------------------
        // (4) Validate or create session.
        // ----------------------------------------
        const std::string session_id = !req_session_id.empty() ? std::string(req_session_id) : generate_session_id();

        auto [it, inserted] = sessions_.try_emplace(std::stoull(session_id), session_id, std::string(username));
        auto &session = it->second;

        if (!inserted) {
            bool owns_session = username == session.owner();
            bool valid_seqnum = std::stoul(std::string(sequence_num)) <= session.sequence_num();

            if (!owns_session || !valid_seqnum) {
                LOG_INFO("client={} failed session subscription check.", client->handle.get());

                const auto reject = msg_login_rejected::build(rej_no_session);
                const auto *reject_buf = reinterpret_cast<const std::byte *>(&reject);
                send_all(client, reject_buf, sizeof(reject));

                to_drop[client->handle.get()] = true;
                continue;
            }
        }

        // ----------------------------------------
        // (5) Send login accepted, subscribe to session.
        // ----------------------------------------
        const auto accept = msg_login_accepted::build(session_id, sequence_num);
        const auto *accept_buf = reinterpret_cast<const std::byte *>(&accept);
        send_all(client, accept_buf, sizeof(accept));

        session.subscribe(client, std::stoul(std::string(sequence_num)));

        LOG_INFO("client={} authenticated and subscribed to session_id={}.", client->handle.get(), session_id);
    }
}

bool server::impl::send_all(const cl_loop_info *client, const std::byte *buf, size_t len) noexcept {
    size_t sent = 0;
    while (sent != len) {
        const ssize_t n = send(client->fd.get(), buf + sent, len - sent, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == ECONNRESET || errno == EPIPE) {
                LOG_DEBUG("client={} disconnected abruptly.", client->handle.get());
                return false;
            }

            if (errno == ENOMEM || errno == ENOBUFS) {
                PANIC("send() failed due to lack of system memory.");
                return false;
            }

            LOG_CRITICAL("send() failed unexpectedly: {}", std::strerror(errno));
            ASSERT_UNREACHABLE();
            return false;
        }

        DEBUG_ASSERT(n > 0);
        sent += n;
    }

    return true;
}

bool server::impl::recv_all(const cl_loop_info *client, std::byte *buf, size_t len, size_t &read) noexcept {
    while (read < len) {
        const ssize_t n = recv(client->fd.get(), buf + read, len - read, MSG_DONTWAIT);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return true;
            }

            if (errno == ECONNRESET) {
                LOG_DEBUG("client={} disconnected abruptly.", client->handle.get());
                return false;
            }

            if (errno == ENOMEM || errno == ENOBUFS) {
                PANIC("recv() failed due to lack of system memory.");
                return false;
            }

            LOG_CRITICAL("recv() failed unexpectedly: {}", std::strerror(errno));
            ASSERT_UNREACHABLE();
            return false;
        }

        if (n == 0) {
            LOG_DEBUG("client={} closed their connection.", client->handle.get());
            return false;
        }

        DEBUG_ASSERT(n > 0);
        read += n;
    }

    return true;
}

// ----------------- factory -----------------

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

    return server(std::make_unique<server::impl>(valid_fd_t{ static_cast<uint16_t>(listener_fd) },
                                                 valid_fd_t{ static_cast<uint16_t>(epoll_fd) }, std::move(cfg)));
}

} // namespace soupbin
