#pragma once

#include "common/types.hpp"

#include <cerrno>
#include <string>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>

namespace soupbin::common {

inline bool verify_fd(common::valid_fd_t fd) { return fcntl(common::ts::get(fd), F_GETFD) != -1; }

} // namespace soupbin::common
