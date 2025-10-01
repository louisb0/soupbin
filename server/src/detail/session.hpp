#pragma once

#include <cstddef>
#include <span>
#include <string>

namespace soupbin::detail {

// TODO
class session {
public:
    [[nodiscard]] const std::string &id() const noexcept;
    void append_sequenced_msg(std::span<const std::byte>);
};

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
