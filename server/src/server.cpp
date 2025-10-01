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
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <span>
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

    [[nodiscard]] std::error_code batch_authed(std::span<cl_loop_info *> authed, drop_list &to_drop,
                                               sent_list &did_send) const noexcept;
    [[nodiscard]] std::error_code batch_unauthed(std::span<cl_loop_info *> unauthed, drop_list &to_drop) noexcept;
};

server::server(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
server::server(server &&other) noexcept = default;
server &server::operator=(server &&) noexcept = default;
server::~server() noexcept = default;

std::error_code server::run() noexcept { return impl_->run(); }

// ---------------- definition ---------------

std::error_code server::impl::run() noexcept {
    while (true) {
        auto [authed, unauthed] = cstore_.ready(cfg_.tick_ms);

        drop_list to_drop;
        sent_list did_send;

        if (auto err = batch_authed(authed, to_drop, did_send); err) {
            break;
        }
        cstore_.assert_consistency();

        if (auto err = batch_unauthed(authed, to_drop); err) {
            break;
        }
        cstore_.assert_consistency();

        // TODO: Session catchup.
        // TODO: Set activity.
        // TODO: Heartbeats.
        // TODO: Drop clients.
        // TODO: Accept clients.
    }

    return {};
}

std::error_code server::impl::batch_authed(std::span<cl_loop_info *> authed, drop_list &to_drop,
                                           sent_list &did_send) const noexcept {
    DEBUG_ASSERT(std::ranges::all_of(authed, [](auto *li) { return li->authed(); }));
    DEBUG_ASSERT(authed.size() <= constants::batch::size);

    if (authed.empty()) {
        return {};
    }

    // --------------------------------
    // (1) Build descriptors.
    // --------------------------------
    alignas(constants::cache_line_sz) std::array<std::byte, constants::bound::max_recv> recv_buffer{};
    alignas(constants::cache_line_sz) std::array<message_descriptor, constants::bound::max_data_msg> msg_descriptors{};
    alignas(constants::cache_line_sz) std::array<uint8_t, constants::batch::size> client_msg_counts{};

    static_assert(recv_buffer.size() == 128 * constants::cache_line_sz);    // NOLINT
    static_assert(msg_descriptors.size() == 32 * constants::cache_line_sz); // NOLINT
    static_assert(client_msg_counts.size() <= constants::cache_line_sz);
    static_assert(std::numeric_limits<decltype(client_msg_counts)::value_type>::max() >= constants::batch::client_data_msg);

    size_t recv_buffer_offset = 0;
    size_t total_msg_count = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        auto *client = authed[i];
        auto *client_buffer = recv_buffer.data() + recv_buffer_offset;

        // Load partial.
        std::memcpy(client_buffer, client->partial.buf.data(), client->partial.len);
        size_t bytes_read = client->partial.len;

        // Receive data.
        while (bytes_read != constants::batch::client_recv) {
            const ssize_t received =
                recv(client->fd.get(), client_buffer + bytes_read, constants::batch::client_recv - bytes_read, MSG_DONTWAIT);

            if (received == -1) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }

                if (errno == ECONNRESET) {
                    LOG_DEBUG("client={} disconnected abruptly, dropping.", client->handle.get());
                    to_drop[client->handle.get()] = true;
                    break;
                }

                if (errno == ENOMEM || errno == ENOBUFS) {
                    PANIC("recv() failed due to lack of system memory.");
                    break;
                }

                LOG_CRITICAL("recv() failed unexpectedly: {}", std::strerror(errno));
                ASSERT_UNREACHABLE();
            }

            if (received == 0) {
                LOG_DEBUG("client={} closed their connection, dropping.", client->handle.get());
                to_drop[client->handle.get()] = true;
                break;
            }

            DEBUG_ASSERT(received > 0);
            DEBUG_ASSERT(bytes_read + received <= constants::batch::client_recv);
            bytes_read += received;
        }

        // Build descriptors.
        size_t bytes_parsed = 0;
        while (bytes_parsed != bytes_read) {
            const size_t bytes_available = bytes_read - bytes_parsed;

            if (bytes_available < sizeof(detail::msg_header)) {
                break;
            }

            const auto *header = reinterpret_cast<const detail::msg_header *>(client_buffer + bytes_parsed);
            const uint16_t payload_length = ntohs(header->length);
            const size_t total_msg_size = sizeof(detail::msg_header) + payload_length;

            if (bytes_available < total_msg_size) {
                break;
            }

            if (payload_length > constants::max_payload_size) {
                LOG_WARN("client={} payload too large at {} bytes, dropping.", client->fd.get(), payload_length);
                to_drop[client->handle.get()] = true;

                FUZZ_UNREACHABLE();
                break;
            }

            DEBUG_ASSERT(bytes_available >= total_msg_size);
            DEBUG_ASSERT(payload_length <= constants::max_payload_size);

            switch (header->type) {
            case detail::mt_debug:
            case detail::mt_unsequenced: {
                // NOTE: ASSERT(payload_length <= constants::max_payload_size) ensures static_cast<uint8_t> is valid.
                static_assert(std::is_same_v<decltype(constants::max_payload_size), const uint8_t>);

                msg_descriptors[total_msg_count++] = {
                    .offset = reinterpret_cast<const std::byte *>(header) + sizeof(detail::msg_header),
                    .len = static_cast<uint8_t>(payload_length),
                    .type = (header->type == detail::mt_debug) ? message_type::debug : message_type::unsequenced,
                };
                client_msg_counts[i]++;

                DEBUG_ASSERT(total_msg_count <= msg_descriptors.size());
                DEBUG_ASSERT(client_msg_counts[i] <= constants::batch::client_data_msg);
                break;
            }

            case mt_logout_request: {
                LOG_DEBUG("client={} requested logout, dropping.", client->handle.get());
                to_drop[client->handle.get()] = true;
                break;
            }

            // NOTE: last_recv is set whenever data is received from a client.
            case detail::mt_client_heartbeat:
                break;

            case detail::mt_login_accepted:
            case detail::mt_login_rejected:
            case detail::mt_sequenced:
            case detail::mt_server_heartbeat:
            case detail::mt_end_of_session:
            case detail::mt_login_request: {
                LOG_WARN("client={} sent unexpected message_type={}, dropping.", client->fd.get(),
                         static_cast<char>(header->type));
                to_drop[client->handle.get()] = true;

                FUZZ_UNREACHABLE();
                break;
            }

            default: {
                LOG_WARN("client={} sent unknown message_type={}, dropping.", client->fd.get(),
                         static_cast<char>(header->type));
                to_drop[client->handle.get()] = true;

                FUZZ_UNREACHABLE();
                break;
            }
            }

            DEBUG_ASSERT(bytes_parsed + total_msg_size <= bytes_read);
            bytes_parsed += total_msg_size;
        }

        // Write-back partial.
        const size_t bytes_remaining = bytes_read - bytes_parsed;
        DEBUG_ASSERT(bytes_remaining < client->partial.buf.size());

        std::memcpy(client->partial.buf.data(), client_buffer + bytes_parsed, bytes_remaining);
        client->partial.len = bytes_remaining;

        // Update position.
        DEBUG_ASSERT(recv_buffer_offset + bytes_parsed <= recv_buffer.size());
        recv_buffer_offset += bytes_parsed;
    }

    // --------------------------------
    // (2) Run callbacks.
    // --------------------------------
    size_t descriptor_offset = 0;

    for (size_t i = 0; i < authed.size(); i++) {
        const auto *client = authed[i];
        const auto msg_count = client_msg_counts[i];
        DEBUG_ASSERT(msg_count <= constants::batch::client_data_msg);

        if (msg_count == 0) {
            continue;
        }

        const std::span<message_descriptor> client_msgs = { &msg_descriptors[descriptor_offset], msg_count };
        for (const auto &msg : client_msgs) {
            DEBUG_ASSERT(msg.type == message_type::debug || msg.type == message_type::unsequenced);
            DEBUG_ASSERT(msg.len <= constants::max_payload_size);
        }

        // NOTE: It is extremely unlikely this buffer fills. It is a tight upper bound used to avoid dynamic allocation.
        alignas(constants::cache_line_sz) std::array<std::byte, constants::batch::client_data_send> reply_buffer{};
        static_assert(reply_buffer.size() == 262 * constants::cache_line_sz); // NOLINT

        // 1. Run callbacks, queue responses.
        size_t reply_size = 0;

        cfg_.on_client_msgs(
            std::string_view(client->sess->id()), client_msgs,
            [&reply_buffer, &reply_size, &did_send, client](message_type type, std::span<const std::byte> payload) {
                if (payload.size() > constants::max_payload_size) {
                    return make_soupbin_error(errc::reply_too_large);
                }

                did_send[client->handle.get()] = true;

                if (type == message_type::sequenced) {
                    client->sess->append_sequenced_msg(payload);
                    return std::error_code{};
                }

                DEBUG_ASSERT(type == message_type::debug || type == message_type::unsequenced);
                DEBUG_ASSERT(reply_size + sizeof(detail::msg_header) + payload.size() <= reply_buffer.size());

                auto *header = reinterpret_cast<detail::msg_header *>(reply_buffer.data() + reply_size);
                header->length = htons(static_cast<uint16_t>(payload.size()));
                header->type = (type == message_type::debug) ? detail::mt_debug : detail::mt_unsequenced;
                std::memcpy(reply_buffer.data() + reply_size + sizeof(detail::msg_header), payload.data(), payload.size());

                reply_size += sizeof(detail::msg_header) + payload.size();
                return std::error_code{};
            });

        DEBUG_ASSERT(reply_size == 0 || reply_size > sizeof(detail::msg_header));

        // 2. Send all data which is not sequenced.
        size_t bytes_sent = 0;
        while (bytes_sent != reply_size) {
            ssize_t sent = send(client->fd.get(), reply_buffer.data() + bytes_sent, reply_size - bytes_sent, MSG_NOSIGNAL);
            if (sent == -1) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == ECONNRESET || errno == EPIPE) {
                    LOG_DEBUG("client={} connection broken, dropping.", client->handle.get());
                    to_drop[client->handle.get()] = true;
                    break;
                }

                if (errno == ENOMEM || errno == ENOBUFS) {
                    PANIC("send() failed due to lack of system memory.");
                    break;
                }

                LOG_CRITICAL("send() failed unexpectedly: {}", std::strerror(errno));
                ASSERT_UNREACHABLE();
            }

            bytes_sent += sent;
        }

        descriptor_offset += msg_count;
    }
    DEBUG_ASSERT(descriptor_offset == total_msg_count);

    return {};
}

std::error_code server::impl::batch_unauthed(std::span<cl_loop_info *> unauthed, drop_list &to_drop) noexcept {
    DEBUG_ASSERT(std::ranges::all_of(unauthed, [](auto *li) { return !li->authed(); }));

    if (unauthed.empty()) {
        return {};
    }

    return {};
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
