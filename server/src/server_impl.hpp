#pragma once

#include "soupbin/server.hpp"

#include "detail/client_manager.hpp"
#include "detail/session.hpp"

#include "common/types.hpp"

#include <string>
#include <unordered_map>

namespace soupbin {

class server::impl {
    friend class server;

public:
    [[nodiscard]] impl(common::valid_fd_t listener, common::valid_fd_t epoll, server_config &&cfg) noexcept
        : cmgr_(epoll, listener), cfg_(std::move(cfg)) {}

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;
    ~impl() = default;

    void run() noexcept;

private:
    common::valid_fd_t listener_;
    detail::client_manager cmgr_;
    std::unordered_map<std::string, detail::session> sessions_;
    server_config cfg_;

    void batch_unauthed(detail::cm_batch_context &ctx) noexcept;
    void batch_authed(detail::cm_batch_context &ctx) const noexcept;

    void assert_consistency() const noexcept;
};

} // namespace soupbin
