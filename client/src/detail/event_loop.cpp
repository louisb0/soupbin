#include "detail/event_loop.hpp"

#include "detail/network.hpp"
#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include "common/messages.hpp"
#include "common/verify.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <compare>
#include <cstddef>
#include <cstring>
#include <optional>
#include <span>
#include <thread>
#include <utility>

#include <arpa/inet.h>
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
    if (thread_.joinable()) {
        thread_.request_stop();
        thread_.join();
    }

    DEBUG_ASSERT(disconnect_reason() != disconnect_reason::none);

    if (close(common::ts::get(fd_)) == -1) {
        LOG_ERROR("failed to close connected fd: {}", std::strerror(errno));
    }
}

// ============================================================================
// Helpers.
// ============================================================================
void ev_loop::start_thread() {
    thread_ = std::jthread([this](const std::stop_token &token) { this->run(token); });
}

void ev_loop::mark_disconnect(enum disconnect_reason reason) {
    DEBUG_ASSERT(disconnect_reason() == disconnect_reason::none);

    const char *reason_str = [reason]() {
        switch (reason) {
        case disconnect_reason::logout:
            return "logout";
            break;
        case disconnect_reason::end_of_session:
            return "end_of_session";
        case disconnect_reason::heartbeat:
            return "heartbeat";
        case disconnect_reason::abrupt_tcp_disconnect:
            return "abrupt_tcp_disconnect";
        case disconnect_reason::orderly_tcp_disconnect:
            return "orderly_tcp_disconnect";
        case disconnect_reason::proto_malformed_length:
            return "proto_malformed_length";
        case disconnect_reason::proto_malformed_type:
            return "proto_malformed_type";
        case disconnect_reason::proto_excessive_length:
            return "proto_excessive_length";
        case disconnect_reason::proto_unexpected_type:
            return "proto_unexpected_type";

        case disconnect_reason::none:
            ASSERT_UNREACHABLE();
            break;
        }

        ASSERT_UNREACHABLE();
        return "unknown";
    }();

    LOG_INFO("event loop disconnecting: {}", reason_str);
    disconnect_reason_.store(reason, std::memory_order_relaxed);
}

enum disconnect_reason ev_loop::disconnect_reason() const noexcept {
    return disconnect_reason_.load(std::memory_order_relaxed);
}

bool ev_loop::connected() const noexcept { return disconnect_reason() == disconnect_reason::none; }

// ============================================================================
// Event loop.
// ============================================================================
void ev_loop::run(const std::stop_token &token) noexcept {
    while (!token.stop_requested() && connected()) {
        const auto now = std::chrono::steady_clock::now();

        // ----------------------------------------
        // (1) Send.
        // ----------------------------------------
        auto queue_slot = send_->read_try_prepare();
        if (!queue_slot.empty()) {
            if (auto failed = detail::send_all(fd_, queue_slot.data(), queue_slot.size())) {
                mark_disconnect(*failed);
                break;
            }

            last_send_ = now;
            send_rb().read_commit(queue_slot.size());
        }

        // ----------------------------------------
        // (2) Receive and processs.
        // ----------------------------------------
        constexpr size_t to_receive = 1024; // TODO

        auto *queue_position = recv_rb().write_try_prepare(to_receive);
        if (queue_position != nullptr) {
            // 2.1 Receive.
            size_t read = partial_.load(queue_position);
            if (auto failed = detail::recv_all(fd_, queue_position, to_receive, read)) {
                mark_disconnect(*failed);
                break;
            }

            if (read > 0) {
                last_recv_ = now;
            }

            // 2.2 Process.
            size_t write_offset = 0;
            size_t parsed = 0;
            while (parsed != read) {
                const size_t available = read - parsed;
                if (available < sizeof(common::msg_header)) {
                    break;
                }

                const auto *header = reinterpret_cast<const common::msg_header *>(queue_position + parsed);
                const size_t payload_length = ntohs(header->length);
                if (payload_length > common::max_payload_size) {
                    mark_disconnect(disconnect_reason::proto_excessive_length);
                    FUZZ_UNREACHABLE();
                    break;
                }

                const size_t message_length = sizeof(common::msg_header) + payload_length;
                if (available < message_length) {
                    break;
                }

                switch (header->type) {
                case common::mt_debug:
                case common::mt_unsequenced:
                case common::mt_sequenced: {
                    if (write_offset != parsed) {
                        std::memmove(queue_position + write_offset, queue_position + parsed, message_length);
                    }

                    write_offset += message_length;
                    break;
                }

                case common::mt_end_of_session: {
                    mark_disconnect(disconnect_reason::end_of_session);
                    break;
                }

                case common::mt_server_heartbeat: {
                    break;
                }

                case common::mt_login_accepted:
                case common::mt_login_rejected:
                case common::mt_client_heartbeat:
                case common::mt_logout_request:
                case common::mt_login_request: {
                    mark_disconnect(disconnect_reason::proto_unexpected_type);
                    FUZZ_UNREACHABLE();
                    break;
                }

                default: {
                    mark_disconnect(disconnect_reason::proto_malformed_type);
                    FUZZ_UNREACHABLE();
                    break;
                }
                }

                DEBUG_ASSERT(parsed + message_length <= read);
                parsed += message_length;
            }

            // 2.3 Commit.
            partial_.store(queue_position + write_offset, read - write_offset, common::partial::client_tag{});
            recv_rb().write_commit(write_offset);
        }

        // ----------------------------------------
        // (3) Heartbeats.
        // ----------------------------------------
        if (now - last_recv_ >= std::chrono::seconds(common::server_heartbeat_sec)) {
            mark_disconnect(disconnect_reason::heartbeat);
            break;
        }

        if (now - last_send_ >= std::chrono::seconds(common::client_heartbeat_sec - 1)) {
            const auto *heartbeat_buf = reinterpret_cast<const std::byte *>(&common::msg_client_heartbeat::prebuilt);
            if (auto failed = detail::send_all(fd_, heartbeat_buf, sizeof(common::msg_server_heartbeat))) {
                mark_disconnect(*failed);
                break;
            }

            last_send_ = now;
        }
    }

    // NOTE: If no error was set, then the user thread requested we log out.
    if (disconnect_reason() == disconnect_reason::none) {
        DEBUG_ASSERT(token.stop_requested());

        auto unsent = send_->read_try_prepare();
        if (!unsent.empty()) {
            if (auto failed = detail::send_all(fd_, unsent.data(), unsent.size())) {
                mark_disconnect(*failed);
                return;
            }
        }

        const auto *logout = reinterpret_cast<const std::byte *>(&common::msg_logout_request::prebuilt);
        if (auto failed = detail::send_all(fd_, logout, sizeof(common::msg_logout_request))) {
            mark_disconnect(*failed);
            return;
        }

        mark_disconnect(disconnect_reason::logout);
    }
}

} // namespace soupbin::detail
