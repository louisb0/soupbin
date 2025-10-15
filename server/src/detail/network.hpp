#pragma once

#include "detail/client_manager.hpp"
#include "detail/types.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <optional>

#include <sys/socket.h>
#include <sys/types.h>

namespace soupbin::detail {

[[nodiscard]] inline std::optional<detail::cm_batch_context::drop_reason>
send_all(const detail::cl_descriptor &descriptor, const std::byte *buf, size_t len) noexcept {
    size_t sent = 0;
    while (sent < len) {
        const ssize_t n = send(common::ts::get(descriptor.fd), buf + sent, len - sent, MSG_NOSIGNAL);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == ECONNRESET || errno == EPIPE) {
                return detail::cm_batch_context::drop_reason::abrupt_disconnect;
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

[[nodiscard]] inline std::optional<detail::cm_batch_context::drop_reason>
recv_all(const detail::cl_descriptor &descriptor, std::byte *buf, size_t len, size_t &read) noexcept {
    while (read < len) {
        const ssize_t n = recv(common::ts::get(descriptor.fd), buf + read, len - read, MSG_DONTWAIT);

        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return std::nullopt;
            }

            if (errno == ECONNRESET) {
                return detail::cm_batch_context::drop_reason::abrupt_disconnect;
            }

            if (errno == ENOMEM || errno == ENOBUFS) {
                PANIC("out of memory.");
            }

            PANIC("unexpected error: {}", std::strerror(errno));
        }

        if (n == 0) {
            return detail::cm_batch_context::drop_reason::graceful_disconnect;
        }

        DEBUG_ASSERT(n > 0);
        read += n;
    }

    return std::nullopt;
}

} // namespace soupbin::detail
