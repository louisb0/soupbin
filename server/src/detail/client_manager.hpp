#pragma once

#include "detail/config.hpp"
#include "detail/types.hpp"

#include "common/partial.hpp"
#include "common/types.hpp"

#include <array>
#include <bitset>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace soupbin::detail {
class session;

// ============================================================================
// Types.
// ============================================================================

struct cl_descriptor {
    common::valid_fd_t fd;
    detail::client_handle_t handle;

    [[nodiscard]] bool operator==(const cl_descriptor &rhs) const noexcept = default;
};

struct cl_random_access {
    detail::session *session{ nullptr };
    cl_descriptor descriptor;
    common::partial partial{};

    [[nodiscard]] bool authed() const noexcept { return session != nullptr; }
};

// ============================================================================
// Batching.
// ============================================================================

class cm_batch_context {
public:
    enum class drop_reason : uint8_t {
        no_heartbeat,
        orderly_logout,
        graceful_disconnect,
        abrupt_disconnect,
        proto_malformed_message,
        proto_malformed_length,
        proto_malformed_seqnum,
        proto_malformed_type,
        proto_excessive_length,
        proto_unexpected_type,
        bad_credentials,
        bad_session,
    };

    [[nodiscard]] cm_batch_context() noexcept = default;
    [[nodiscard]] cm_batch_context(std::span<cl_random_access *const> ready, detail::client_count_t auth_end) noexcept;

    cm_batch_context(const cm_batch_context &) = delete;
    cm_batch_context &operator=(const cm_batch_context &) = delete;
    cm_batch_context(cm_batch_context &&) noexcept = default;
    cm_batch_context &operator=(cm_batch_context &&) noexcept = default;
    ~cm_batch_context() = default;

    void mark_drop(detail::client_handle_t handle, drop_reason reason) noexcept;
    void mark_sent(detail::client_handle_t handle) noexcept { sent_list_[common::ts::get(handle)] = true; }

    [[nodiscard]] auto all() const noexcept { return ready_; }
    [[nodiscard]] auto authed() const noexcept { return ready_.subspan(0, common::ts::get(auth_end_)); }
    [[nodiscard]] auto unauthed() const noexcept { return ready_.subspan(common::ts::get(auth_end_)); }
    [[nodiscard]] bool empty() const noexcept { return ready_.empty(); }

    [[nodiscard]] bool dropped(detail::client_handle_t handle) const noexcept { return drop_list_[common::ts::get(handle)]; }

private:
    friend class client_manager;

    std::bitset<detail::max_clients> drop_list_;
    std::bitset<detail::max_clients> sent_list_;

    std::span<cl_random_access *const> ready_;
    detail::client_count_t auth_end_{};
};

// ============================================================================
// Manager.
// ============================================================================

class client_manager {
public:
    [[nodiscard]] client_manager(common::valid_fd_t epoll, common::valid_fd_t listener) noexcept;
    ~client_manager();

    client_manager(client_manager &) = delete;
    client_manager &operator=(client_manager &) = delete;
    client_manager(client_manager &&) = delete;
    client_manager &operator=(client_manager &&) = delete;

    size_t onboard(detail::client_count_t max) noexcept;
    [[nodiscard]] cm_batch_context poll(std::chrono::milliseconds timeout) noexcept;
    void process(cm_batch_context &ctx) noexcept;

    [[nodiscard]] size_t capacity() const noexcept { return random_access_.capacity(); }
    [[nodiscard]] size_t size() const noexcept { return random_access_.size(); }

    // NOLINTNEXTLINE(modernize-use-nodiscard)
    const std::vector<detail::cl_random_access> &assert_consistency() const noexcept;

private:
    struct cl_activity_info {
        std::chrono::steady_clock::time_point last_send;
        std::chrono::steady_clock::time_point last_recv;
    };

    union cl_epoll_data {
        uint32_t u32{};
        cl_descriptor descriptor;

        static_assert(sizeof(descriptor) == sizeof(u32));
    };

    const common::valid_fd_t epoll_;
    const common::valid_fd_t listener_;
    const detail::client_count_t capacity_;

    std::vector<cl_random_access> random_access_;
    std::vector<cl_activity_info> activity_info_;
    std::array<cl_random_access *, detail::batch_size> ready_buffer_{};
};

} // namespace soupbin::detail

namespace std {

template <>
struct hash<soupbin::detail::cl_descriptor> {
    // https://www.boost.org/doc/libs/1_35_0/doc/html/boost/hash_combine_id241013.html
    size_t operator()(const soupbin::detail::cl_descriptor &id) const noexcept {
        size_t seed = 0;
        seed ^= std::hash<soupbin::common::valid_fd_t>{}(id.fd) + 0x9e3779b9 + (seed << 6) + (seed >> 2);          // NOLINT
        seed ^= std::hash<soupbin::detail::client_handle_t>{}(id.handle) + 0x9e3779b9 + (seed << 6) + (seed >> 2); // NOLINT
        return seed;
    }
};

} // namespace std
