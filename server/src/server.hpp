#pragma once

#include "soupbin/server.hpp"

#include "detail/client_manager.hpp"
#include "detail/config.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include <array>
#include <cstddef>
#include <span>
#include <unordered_map>

namespace soupbin {

class server::impl {
    detail::valid_fd_t listener_;
    detail::client_manager cmgr_;
    std::unordered_map<std::string, detail::session> sessions_;

    server_config cfg_;

public:
    [[nodiscard]] impl(detail::valid_fd_t listener, detail::valid_fd_t epoll, server_config &&cfg) noexcept;

    impl(const impl &) = delete;
    impl &operator=(const impl &) = delete;
    impl(impl &&) = delete;
    impl &operator=(impl &&) = delete;
    ~impl() = default;

    void run() noexcept;

private:
    void batch_unauthed(detail::cm_batch_context &ctx) noexcept;
    void batch_authed(detail::cm_batch_context &ctx) const noexcept;

    void assert_consistency() const noexcept;
};

} // namespace soupbin
