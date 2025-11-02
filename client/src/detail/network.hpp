#pragma once

#include "soupbin/client.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/types.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <optional>

#include <sys/socket.h>
#include <sys/types.h>

// TODO: Duplication with server.
namespace soupbin::detail {

[[nodiscard]] inline std::optional<disconnect_reason> send_all(common::valid_fd_t fd, const std::byte *buf,
                                                               size_t len) noexcept {
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = send(common::ts::get(fd), buf + sent, len - sent, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == ECONNRESET || errno == EPIPE) {
                return disconnect_reason::abrupt_tcp_disconnect;
            }

            if (errno == ENOMEM || errno == ENOBUFS) {
                PANIC("out of memory.");
            }

            PANIC("unexpected error: {}", std::strerror(errno));
        }

        DEBUG_ASSERT(n > 0);
        sent += n;
    }

    return std::nullopt;
}

[[nodiscard]] inline std::optional<disconnect_reason> recv_all(common::valid_fd_t fd, std::byte *buf, size_t len,
                                                               size_t &read) noexcept {
    while (read < len) {
        const ssize_t n = recv(common::ts::get(fd), buf + read, len - read, MSG_DONTWAIT);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return std::nullopt;
            }

            if (errno == ECONNRESET) {
                return disconnect_reason::abrupt_tcp_disconnect;
            }

            if (errno == ENOMEM || errno == ENOBUFS) {
                PANIC("out of memory.");
            }

            PANIC("unexpected error: {}", std::strerror(errno));
        }

        if (n == 0) {
            return disconnect_reason::orderly_tcp_disconnect;
        }

        DEBUG_ASSERT(n > 0);
        read += n;
    }

    return std::nullopt;
}

} // namespace soupbin::detail
