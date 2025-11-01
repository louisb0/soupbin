#include "detail/event_loop.hpp"

#include "detail/config.hpp"
#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/messages.hpp"
#include "common/verify.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <span>
#include <system_error>
#include <thread>
#include <utility>

#include <sys/socket.h>
#include <sys/types.h>
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
    thread_.request_stop();
    if (thread_.joinable()) {
        thread_.join();
    }

    if (close(common::ts::get(fd_)) == -1) {
        LOG_ERROR("failed to close connected fd: {}", std::strerror(errno));
    }
}

void ev_loop::start_thread() {
    thread_ = std::jthread([this](const std::stop_token &token) { this->run(token); });
}

std::error_code ev_loop::error() const noexcept {
    int error = errno_.load(std::memory_order_relaxed);
    if (error == detail::no_error) {
        return {};
    }

    return { error, std::system_category() };
}

void ev_loop::run(const std::stop_token &token) noexcept {
    while (!token.stop_requested()) {
        auto queue_slot = send().read_try_prepare();
        if (!queue_slot.empty()) {
            ssize_t bytes = ::send(common::ts::get(fd_), queue_slot.data(), queue_slot.size(), 0);
            DEBUG_ASSERT(bytes > 0);
            send().read_commit(bytes);
        }

        auto *queue_position = recv().write_prepare(1024);                     // NOLINT
        ssize_t bytes = ::recv(common::ts::get(fd_), queue_position, 1024, 0); // NOLINT
        if (bytes == -1) {
            DEBUG_ASSERT(errno == EAGAIN || errno == EWOULDBLOCK);
        } else {
            DEBUG_ASSERT(bytes > 0);
            recv().write_commit(bytes);
        }
    }

    if (!error()) {
        const auto *request = &common::msg_logout_request::prebuilt;
        if (::send(common::ts::get(fd_), request, sizeof(*request), 0) == -1) {
            LOG_CRITICAL("failed to send() logout request.");
        }
    }
}

} // namespace soupbin::detail
