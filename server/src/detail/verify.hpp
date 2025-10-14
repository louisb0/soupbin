#pragma once

#include "detail/types.hpp"

#include <cerrno>
#include <string>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace soupbin::detail {

inline bool verify_fd(detail::valid_fd_t fd) { return fcntl(ts::get(fd), F_GETFD) != -1; }

inline bool verify_listener(detail::valid_fd_t fd) {
    int listening = 0;
    socklen_t len = sizeof(listening);
    if (getsockopt(detail::ts::get(fd), SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) == -1) {
        return false;
    }
    return listening != 0;
}

inline bool verify_epoll(detail::valid_fd_t fd) {
    struct epoll_event ev{};
    int result = epoll_wait(detail::ts::get(fd), &ev, 1, 0);
    return result >= 0 || (result == -1 && errno == EINTR);
}

} // namespace soupbin::detail
