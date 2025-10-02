#pragma once

#include "detail/messages.hpp"

#include <cstddef>
#include <random>
#include <span>
#include <string>

namespace soupbin::detail {
struct cl_loop_info;

// TODO
class session {
public:
    session(std::string id, std::string owner);

    void subscribe(const cl_loop_info *client, size_t sequence_num);

    [[nodiscard]] const std::string &owner() const noexcept;
    [[nodiscard]] size_t sequence_num() const noexcept;

    [[nodiscard]] const std::string &id() const noexcept;
    void append_sequenced_msg(std::span<const std::byte>);
};

// NOLINTBEGIN
inline std::string generate_session_id() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);

    std::string result;
    result.reserve(detail::session_id_len);

    for (size_t i = 0; i < detail::session_id_len; ++i) {
        int val = dis(gen);
        result += (val < 10) ? ('0' + val) : ('a' + val - 10);
    }

    return result;
}
// NOLINTEND

// class client_store;
// struct cl_loop_info;
//
// struct sn_subscriber {
//     client_handle_t handle;
//     valid_fd_t fd;
//     uint32_t cursor{};
// };
//
// class session {
//     std::string owner_; // TODO: Should a string be used?
//     std::string id_;
//
//     std::vector<std::byte> stream_;
//     std::vector<size_t> boundaries_;
//     std::vector<sn_subscriber> subscribers_;
//
// public:
//     [[nodiscard]] session() noexcept = default;
//     ~session() = default;
//
//     session(const session &) = delete;
//     session &operator=(const session &) = delete;
//     session(session &&) noexcept = default;
//     session &operator=(session &&) noexcept = default;
//
//     void subscribe(cl_loop_info *) noexcept;
//     void add_seq_msg(std::span<const std::byte>) noexcept;
//
//     // TODO: should the session even be sending? idk.  tthink thats drivers job. see couploing with dro lsit? bad.
//     void broadcast(std::vector<client_handle_t> &drop_list) noexcept;
//
//     [[nodiscard]] const std::string &owner() const noexcept;
//     [[nodiscard]] const std::string &id() const noexcept;
//     [[nodiscard]] std::span<const sn_subscriber> subscribers() const noexcept;
//
//     void assert_consistency();
// };

} // namespace soupbin::detail
