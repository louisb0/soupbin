#include "client_store.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"

#include "verify.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ranges>

#include <sys/epoll.h>
#include <unistd.h>

namespace soupbin {

client_store::client_store(valid_fd_t epoll, client_handle_t max_clients) noexcept
    : epoll_(epoll), max_clients_(max_clients) {
    ASSERT(verify::fd(epoll));
    ASSERT(verify::epoll(epoll));

    loop_info_.reserve(max_clients.get());
    activity_info_.reserve(max_clients.get());
}

client_store::~client_store() {
    if (close(epoll_.get()) == -1) {
        LOG_ERROR("close(epoll={}) failed: {}", epoll_.get(), std::strerror(errno));
    }
}

std::span<cl_loop_info *> client_store::ready(int timeout_ms) noexcept {
    DEBUG_ASSERT(verify::epoll(epoll_));
    DEBUG_ASSERT(loop_info_.size() == activity_info_.size()); // SoA consistency.

    const int nfds = epoll_wait(epoll_.get(), event_buffer_.data(), static_cast<int>(event_buffer_.size()), timeout_ms);
    if (nfds == -1) {
        if (errno == EINTR) {
            return {};
        }

        LOG_CRITICAL("epoll_wait() failed unexpectedly: {}", std::strerror(errno));
        ASSERT_UNREACHABLE();
    }

    const auto nready = static_cast<size_t>(nfds);
    DEBUG_ASSERT(nready <= loop_info_.size());

    // NOLINTBEGIN(*-array-index)
    for (size_t i = 0; i < nready; i++) {
        const cl_epoll_data data{ .u32 = event_buffer_[i].data.u32 };
        const auto handle = data.parts.handle;

        DEBUG_ASSERT(handle < loop_info_.size());
        DEBUG_ASSERT(loop_info_[handle].handle.get() == handle);
        DEBUG_ASSERT(loop_info_[handle].fd.get() == data.parts.fd);

        ready_buffer_[i] = std::addressof(loop_info_[handle]);
    }
    // NOLINTEND(*-array-index)

    // NOTE: Group by session so that clients on the same session are processed contiguously,
    // keeping both our session data and the user's session-associated structures hot in cache.
    auto ready = std::span{ ready_buffer_.data(), nready };
    std::ranges::sort(ready, [](const auto *a, const auto *b) { return a->sess > b->sess; });

    return ready;
}

void client_store::add(std::span<const valid_fd_t> fds) noexcept {
    DEBUG_ASSERT(verify::epoll(epoll_));
    DEBUG_ASSERT(loop_info_.size() == activity_info_.size());              // SoA consistency.
    DEBUG_ASSERT(loop_info_.capacity() == max_clients_.get());             // No resize.
    DEBUG_ASSERT(activity_info_.capacity() == max_clients_.get());         // No resize.
    DEBUG_ASSERT(loop_info_.size() + fds.size() <= loop_info_.capacity()); // No resize.

    const auto now = std::chrono::steady_clock::now();

    for (const auto &fd : fds) {
        auto it = std::ranges::find_if(loop_info_, [fd](const auto &li) { return li.fd.get() == fd.get(); });
        DEBUG_ASSERT(verify::fd(fd));
        DEBUG_ASSERT(it == loop_info_.end());

        const auto ch = client_handle_t(loop_info_.size());

        // Add to store.
        loop_info_.push_back(cl_loop_info{
            .sess = nullptr,
            .fd = fd,
            .handle = ch,
            .partial = { .len = 0, .buf = {} },
        });
        activity_info_.push_back(cl_activity_info{ .last_send = {}, .last_recv = now });

        // Add to epoll.
        epoll_event ev{ .events = EPOLLIN, .data = {
                .u32 = cl_epoll_data{
                    .parts = { .fd = fd.get(), .handle = ch.get() },
                }.u32,
            },
        };

        if (epoll_ctl(epoll_.get(), EPOLL_CTL_ADD, fd.get(), &ev) == -1) {
            if (errno == ENOMEM) {
                PANIC("epoll_ctl(EPOLL_CTL_ADD) failed due to lack of memory. (ENOMEM)");
            }

            if (errno == ENOSPC) {
                PANIC("epoll_ctl(EPOLL_CTL_ADD) failed due to system limit /proc/sys/fs/epoll/max_user_watches. (ENOSPC)");
            }

            LOG_CRITICAL("epoll_ctl(EPOLL_CTL_ADD) failed unexpectedly: {}", std::strerror(errno));
            ASSERT_UNREACHABLE();
        }
    }

    DEBUG_ASSERT(loop_info_.size() == activity_info_.size());
    DEBUG_ASSERT(loop_info_.capacity() == max_clients_.get());
    DEBUG_ASSERT(activity_info_.capacity() == max_clients_.get());
}

void client_store::remove(std::span<client_handle_t> chs) noexcept {
    DEBUG_ASSERT(verify::epoll(epoll_));
    DEBUG_ASSERT(loop_info_.size() == activity_info_.size()); // SoA consistency.
    DEBUG_ASSERT(chs.size() <= loop_info_.size());            // All clients can exist in store.

    // Decreasing order to prevent invalidation of any removal target.
    std::ranges::sort(chs, [](const auto &a, const auto &b) { return a.get() > b.get(); });

    for (const auto &ch : chs) {
        DEBUG_ASSERT(ch.get() < loop_info_.size());
        DEBUG_ASSERT(ch.get() == loop_info_[ch.get()].handle.get());

        // Swap and update.
        bool removing_last = ch.get() == loop_info_.size() - 1;
        if (!removing_last) {
            std::swap(loop_info_[ch.get()], loop_info_.back());
            std::swap(activity_info_[ch.get()], activity_info_.back());

            loop_info_[ch.get()].handle = ch;

            epoll_event ev{ .events = EPOLLIN, .data = {
                    .u32 = cl_epoll_data{
                        .parts = { .fd = loop_info_[ch.get()].fd.get(), .handle = ch.get() },
                    }.u32,
                },
            };

            if (epoll_ctl(epoll_.get(), EPOLL_CTL_MOD, loop_info_[ch.get()].fd.get(), &ev) == -1) {
                if (errno == ENOMEM) {
                    PANIC("epoll_ctl(EPOLL_CTL_MOD) failed due to lack of memory. (ENOMEM)");
                }

                LOG_CRITICAL("epoll_ctl(EPOLL_CTL_MOD) failed unexpectedly: {}", std::strerror(errno));
                ASSERT_UNREACHABLE();
            }
        }

        // Remove.
        valid_fd_t to_remove = loop_info_.back().fd;

        if (epoll_ctl(epoll_.get(), EPOLL_CTL_DEL, to_remove.get(), nullptr) == -1) {
            if (errno == ENOMEM) {
                PANIC("epoll_ctl(EPOLL_CTL_DEL) failed due to lack of memory. (ENOMEM)");
            }

            LOG_CRITICAL("epoll_ctl(EPOLL_CTL_DEL) failed unexpectedly: {}", std::strerror(errno));
            ASSERT_UNREACHABLE();
        }

        if (close(to_remove.get()) == -1) {
            LOG_ERROR("close(to_remove={}) failed: {}", to_remove.get(), std::strerror(errno));
        }

        loop_info_.pop_back();
        activity_info_.pop_back();
    }

    DEBUG_ASSERT(loop_info_.size() == activity_info_.size()); // SoA consistency.
}

std::span<const cl_activity_info> client_store::activity() const noexcept { return activity_info_; }

cl_activity_info &client_store::activity_info(client_handle_t ch) noexcept {
    DEBUG_ASSERT(loop_info_.size() == activity_info_.size());
    DEBUG_ASSERT(ch.get() < activity_info_.size());
    DEBUG_ASSERT(ch.get() == loop_info_[ch.get()].handle.get());

    return activity_info_[ch.get()];
}

bool client_store::full() const noexcept { return loop_info_.size() == max_clients_.get(); }
size_t client_store::size() const noexcept { return loop_info_.size(); }

void client_store::assert_consistency() const noexcept {
    // Invariant(1): valid epoll instance.
    DEBUG_ASSERT(verify::fd(epoll_));
    DEBUG_ASSERT(verify::epoll(epoll_));

    // Invariant(2): SoA synchronisation.
    DEBUG_ASSERT(loop_info_.size() == activity_info_.size());

    // Invariant(3): SoA no-resize.
    DEBUG_ASSERT(loop_info_.capacity() == max_clients_.get());
    DEBUG_ASSERT(activity_info_.capacity() == max_clients_.get());

    // Invariant(4): client field stability.
    for (size_t i = 0; i < loop_info_.size(); i++) {
        const auto &li = loop_info_[i];

        DEBUG_ASSERT(verify::fd(li.fd));
        DEBUG_ASSERT(li.handle.get() == i);
        DEBUG_ASSERT(li.partial.len <= li.partial.buf.size());

        // TODO: Session assertions.
    }
}

} // namespace soupbin
