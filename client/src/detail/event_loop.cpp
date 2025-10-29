#include "detail/event_loop.hpp"

#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/verify.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <utility>

#include <unistd.h>

namespace soupbin::detail {

ev_loop::ev_loop(common::valid_fd_t fd, std::unique_ptr<detail::spsc_ringbuf> send,
                 std::unique_ptr<detail::spsc_ringbuf> recv) noexcept
    : fd_(fd), send_(std::move(send)), recv_(std::move(recv)) {
    DEBUG_ASSERT(common::verify_fd(fd_));
    DEBUG_ASSERT(send_ != nullptr);
    DEBUG_ASSERT(recv_ != nullptr);
}

ev_loop::~ev_loop() {
    if (close(common::ts::get(fd_)) == -1) {
        LOG_ERROR("failed to close connected fd: {}", std::strerror(errno));
    }
}

void ev_loop::start_thread() {
    thread_ = std::jthread([this](const std::stop_token &token) { this->run(token); });
}

void ev_loop::run(const std::stop_token &token) noexcept {
    while (!token.stop_requested()) {
        LOG_INFO("{}", fd_);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

} // namespace soupbin::detail
