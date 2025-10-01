#pragma once

#include "detail/types.hpp"

#include <cerrno>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace soupbin::detail::verify {

inline bool fd(valid_fd_t fd) { return fcntl(fd.get(), F_GETFD) != -1; }

inline bool listener(valid_fd_t fd) {
    int listening = 0;
    socklen_t len = sizeof(listening);
    if (getsockopt(fd.get(), SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) == -1) {
        return false;
    }
    return listening != 0;
}

inline bool epoll(valid_fd_t fd) {
    struct epoll_event ev{};
    int result = epoll_wait(fd.get(), &ev, 1, 0);
    return result >= 0 || (result == -1 && errno == EINTR);
}

template <typename T>
constexpr bool no_padding() {
    return std::has_unique_object_representations_v<T>;
}

} // namespace soupbin::detail::verify
