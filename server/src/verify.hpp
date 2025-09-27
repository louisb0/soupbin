#pragma once

#include "types.hpp"

#include <cerrno>

#include <fcntl.h>
#include <sys/epoll.h>

namespace soupbin::verify {

inline bool fd(valid_fd_t fd) { return fcntl(fd.get(), F_GETFD) != -1; }

inline bool epoll(valid_fd_t fd) {
    struct epoll_event ev{};
    int result = epoll_wait(fd.get(), &ev, 1, 0);
    return result >= 0 || (result == -1 && errno == EINTR);
}

} // namespace soupbin::verify
