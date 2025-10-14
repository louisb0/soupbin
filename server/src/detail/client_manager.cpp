#include "detail/client_manager.hpp"

#include "detail/config.hpp"
#include "detail/messages.hpp"
#include "detail/network.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"
#include "detail/verify.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <compare>
#include <cstring>
#include <functional>
#include <optional>
#include <ranges>
#include <unordered_set>
#include <utility>

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace soupbin::detail {

// ============================================================================
// Batching.
// ============================================================================

cm_batch_context::cm_batch_context(std::span<cl_random_access *const> ready, detail::client_count_t auth_end) noexcept
    : ready_(ready), auth_end_(auth_end) {
    DEBUG_ASSERT(auth_end_ <= ready.size());
    DEBUG_ASSERT(ready_.size() <= detail::batch_size);

    DEBUG_ASSERT(authed().size() + unauthed().size() == ready.size());
    DEBUG_ASSERT(std::ranges::all_of(authed(), [](const auto *cl) { return cl->authed(); }));
    DEBUG_ASSERT(std::ranges::none_of(unauthed(), [](const auto *cl) { return cl->authed(); }));
}

void cm_batch_context::mark_drop(detail::client_handle_t handle, drop_reason reason) noexcept {
    const char *reason_str = [reason]() {
        switch (reason) {
        case drop_reason::no_heartbeat:
            return "no_heartbeat";
        case drop_reason::orderly_logout:
            return "orderly_logout";
        case drop_reason::graceful_disconnect:
            return "graceful_disconnect";
        case drop_reason::abrupt_disconnect:
            return "abrupt_disconnect";
        case drop_reason::proto_malformed_message:
            return "proto_malformed_message";
        case drop_reason::proto_malformed_length:
            return "proto_malformed_length";
        case drop_reason::proto_malformed_type:
            return "proto_malformed_type";
        case drop_reason::proto_excessive_length:
            return "proto_excessive_length";
        case drop_reason::proto_unexpected_type:
            return "proto_unexpected_type";
        case drop_reason::bad_credentials:
            return "bad_credentials";
        case drop_reason::bad_session:
            return "bad_session";
        }

        ASSERT_UNREACHABLE();
        return "unknown";
    }();

    drop_list_[detail::ts::get(handle)] = true;
    LOG_INFO("client={} added to drop list (reason={})", detail::ts::get(handle), reason_str);
}

// ============================================================================
// Manager.
// ============================================================================

#define DEBUG_ASSERT_SOA()                                                                                                  \
    DEBUG_ASSERT(random_access_.size() == activity_info_.size());                                                           \
    DEBUG_ASSERT(random_access_.capacity() == activity_info_.capacity());                                                   \
    DEBUG_ASSERT(random_access_.capacity() == capacity_)

client_manager::client_manager(detail::valid_fd_t epoll, detail::valid_fd_t listener) noexcept
    : epoll_(epoll), listener_(listener), capacity_(detail::max_clients) {
    ASSERT(detail::verify_epoll(epoll_));
    ASSERT(detail::verify_listener(listener_));

    random_access_.reserve(detail::ts::get(capacity_));
    activity_info_.reserve(detail::ts::get(capacity_));
}

client_manager::~client_manager() {
    if (close(detail::ts::get(epoll_)) == -1) {
        LOG_ERROR("failed to close epoll instance: {}", std::strerror(errno));
    }

    if (close(detail::ts::get(listener_)) == -1) {
        LOG_ERROR("failed to close listener socket: {}", std::strerror(errno));
    }
}

size_t client_manager::onboard(detail::client_count_t max) noexcept {
    DEBUG_ASSERT(detail::verify_epoll(epoll_));
    DEBUG_ASSERT(detail::verify_listener(listener_));
    DEBUG_ASSERT_SOA();

    const auto now = std::chrono::steady_clock::now();

    const size_t available = random_access_.capacity() - size();
    const size_t attempts = std::min(static_cast<size_t>(detail::ts::get(max)), available);

    size_t accepted = 0;
    for (size_t i = 0; i < attempts; i++) {
        sockaddr_in addr{};
        socklen_t addrlen = sizeof(addr);

        // ----------------------------------------
        // (1) Accept.
        // ----------------------------------------
        int fd = accept(detail::ts::get(listener_), reinterpret_cast<sockaddr *>(&addr), &addrlen);
        if (fd == -1) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                break;
            }

            if (errno == ENOMEM) {
                PANIC("out of memory.");
            }

            PANIC("unexpected errno: ", std::strerror(errno));
        }

        // ----------------------------------------
        // (2) Add.
        // ----------------------------------------
        const cl_descriptor desc{
            .fd = detail::valid_fd_t(fd),
            .handle = detail::client_handle_t(random_access_.size()),
        };

        epoll_event ev{
            .events = EPOLLIN,
            .data = { .u32 = cl_epoll_data{ .descriptor = desc }.u32 },
        };
        if (epoll_ctl(detail::ts::get(epoll_), EPOLL_CTL_ADD, detail::ts::get(desc.fd), &ev) == -1) {
            if (errno == ENOMEM) {
                PANIC("out of memory.");
            }

            if (errno == ENOSPC) {
                PANIC("/proc/sys/fs/epoll/max_user_watches reached");
            }

            PANIC("unexpected errno: ", std::strerror(errno));
        }

        random_access_.push_back(cl_random_access{ .descriptor = desc });
        activity_info_.push_back(cl_activity_info{ .last_send = now, .last_recv = now });

        accepted++;
    }

    DEBUG_ASSERT_SOA();
    for (size_t i = random_access_.size() - accepted; i < random_access_.size(); i++) {
        DEBUG_ASSERT(random_access_[i].descriptor.handle == i);
    }

    return accepted;
}

cm_batch_context client_manager::poll(std::chrono::milliseconds timeout) noexcept {
    DEBUG_ASSERT(detail::verify_epoll(epoll_));

    // ----------------------------------------
    // (1) Poll.
    // ----------------------------------------
    std::array<epoll_event, detail::batch_size> events{};
    const int nfds = epoll_wait(detail::ts::get(epoll_), events.data(), static_cast<int>(events.size()),
                                static_cast<int>(timeout.count()));
    if (nfds == -1) {
        if (errno == EINTR) {
            return {};
        }

        PANIC("unexpected error: {}", std::strerror(errno));
        return {};
    }

    for (size_t i = 0; i < static_cast<size_t>(nfds); i++) {
        const cl_epoll_data data{ .u32 = events[i].data.u32 };
        const auto handle = data.descriptor.handle;

        DEBUG_ASSERT(handle < random_access_.size());
        DEBUG_ASSERT(random_access_[detail::ts::get(handle)].descriptor.handle == handle);
        DEBUG_ASSERT(random_access_[detail::ts::get(handle)].descriptor.fd == data.descriptor.fd);

        ready_buffer_[i] = std::addressof(random_access_[detail::ts::get(handle)]);
    }

    // ----------------------------------------
    // (2) Group.
    // ----------------------------------------
    auto ready = std::span{ ready_buffer_.data(), static_cast<size_t>(nfds) };
    std::ranges::sort(ready, [](const auto *a, const auto *b) { return std::greater<void *>{}(a->session, b->session); });

    size_t auth_end = 0;
    while (auth_end < ready.size() && ready[auth_end]->authed()) {
        auth_end++;
    }

    return { ready, detail::client_count_t(auth_end) };
}

void client_manager::process(cm_batch_context &ctx) noexcept {
    DEBUG_ASSERT(detail::verify_epoll(epoll_));

    DEBUG_ASSERT(ctx.sent_list_._Find_next(activity_info_.size() - 1) == ctx.sent_list_.size()); // OoB check.
    DEBUG_ASSERT(ctx.drop_list_._Find_next(random_access_.size() - 1) == ctx.drop_list_.size());

    // ----------------------------------------
    // (1) Heartbeats.
    // ----------------------------------------
    const auto now = std::chrono::steady_clock::now();

    // 1.1 Update activity.
    for (size_t i = 0; i < activity_info_.size(); i++) {
        auto &[last_send, _] = activity_info_[i];

        if (ctx.sent_list_[i]) {
            last_send = now;
        }
    }

    // NOTE(perf): activity_info_ in L1 for random access following predictable linear walk.
    for (const auto *client : ctx.all()) {
        activity_info_[detail::ts::get(client->descriptor.handle)].last_recv = now;
    }

    // 1.2 Process heartbeats.
    for (size_t i = 0; i < activity_info_.size(); i++) {
        auto &[last_send, last_recv] = activity_info_[i];

        if (now - last_recv >= std::chrono::seconds(detail::client_heartbeat_sec)) {
            ctx.mark_drop(detail::client_handle_t(i), cm_batch_context::drop_reason::no_heartbeat);
            continue;
        }

        if (now - last_send >= std::chrono::seconds(detail::server_heartbeat_sec - 1)) {
            static const auto heartbeat = detail::msg_server_heartbeat::build();
            static const auto *heartbeat_buf = reinterpret_cast<const std::byte *>(&heartbeat);

            auto &client = random_access_[i];
            if (auto failed = detail::send_all(client.descriptor, heartbeat_buf, sizeof(heartbeat))) {
                ctx.mark_drop(client.descriptor.handle, *failed);
                continue;
            }
        }
    }

    // ----------------------------------------
    // (2) Client removal (swap-pop).
    // ----------------------------------------
    DEBUG_ASSERT_SOA();

    for (size_t i = random_access_.size(); i-- > 0;) {
        if (!ctx.drop_list_[i]) {
            continue;
        }

        // 2.1 Swap.
        bool is_last_element = (i == random_access_.size() - 1);
        if (!is_last_element) {
            std::swap(random_access_[i], random_access_.back());
            std::swap(activity_info_[i], activity_info_.back());

            auto &swapped = random_access_[i];
            const cl_descriptor old_descriptor = swapped.descriptor;

            swapped.descriptor.handle = detail::client_handle_t(i);

            epoll_event ev{
                .events = EPOLLIN,
                .data = { .u32 = cl_epoll_data{ .descriptor = swapped.descriptor }.u32 },
            };
            if (epoll_ctl(detail::ts::get(epoll_), EPOLL_CTL_MOD, detail::ts::get(swapped.descriptor.fd), &ev) == -1) {
                if (errno == ENOMEM) {
                    PANIC("out of memory.");
                }

                PANIC("unexpected error: {}", std::strerror(errno));
            }

            if (swapped.authed()) {
                auto it = std::ranges::find_if(swapped.session->subscribers(),
                                               [&](const auto &sub) { return sub.descriptor == old_descriptor; });
                DEBUG_ASSERT(it != swapped.session->subscribers().end());
                it->descriptor = swapped.descriptor;
            }
        }

        // 2.2 Pop.
        auto &to_pop = random_access_.back();

        if (epoll_ctl(detail::ts::get(epoll_), EPOLL_CTL_DEL, detail::ts::get(to_pop.descriptor.fd), nullptr) == -1) {
            if (errno == ENOMEM) {
                PANIC("out of memory.");
            }

            PANIC("unexpected error: {}", std::strerror(errno));
        }
        if (close(detail::ts::get(to_pop.descriptor.fd)) == -1) {
            LOG_ERROR("client={} failed to close socket: {}", to_pop.descriptor.handle, std::strerror(errno));
        }

        if (to_pop.authed()) {
            to_pop.session->unsubscribe(to_pop);
        }

        random_access_.pop_back();
        activity_info_.pop_back();
    }

    DEBUG_ASSERT_SOA();
}

const std::vector<cl_random_access> &client_manager::assert_consistency() const noexcept {
#ifndef NDEBUG
    DEBUG_ASSERT(detail::verify_epoll(epoll_));
    DEBUG_ASSERT(detail::verify_listener(listener_));

    DEBUG_ASSERT_SOA();

    std::unordered_set<detail::valid_fd_t> seen_fds;
    for (size_t i = 0; i < random_access_.size(); i++) {
        const auto &client = random_access_[i];

        DEBUG_ASSERT(client.descriptor.handle == i);

        DEBUG_ASSERT(detail::verify_fd(client.descriptor.fd));
        DEBUG_ASSERT(!seen_fds.contains(client.descriptor.fd));
        seen_fds.insert(client.descriptor.fd);

        if (client.authed()) {
            DEBUG_ASSERT(std::ranges::count(client.session->subscribers(), client.descriptor,
                                            &detail::sn_subscriber::descriptor) == 1);
        }
    }
#endif
    return random_access_;
}

} // namespace soupbin::detail
