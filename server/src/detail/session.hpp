#pragma once

#include "detail/client_manager.hpp"
#include "detail/types.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace soupbin::detail {

// ============================================================================
// Types.
// ============================================================================

struct sn_subscriber {
    detail::cl_descriptor descriptor;
    uint32_t _reserved{};
    detail::seq_num_t seq_num;
};

// ============================================================================
// Session.
// ============================================================================

class session {
public:
    [[nodiscard]] session(std::string id, std::string owner) noexcept;

    session(const session &) = delete;
    session &operator=(const session &) = delete;
    session(session &&) noexcept = default;
    session &operator=(session &&) noexcept = default;
    ~session() = default;

    void subscribe(detail::cl_random_access &client, detail::seq_num_t from) noexcept;
    void unsubscribe(detail::cl_random_access &client) noexcept;
    void append_seq_msg(std::span<const std::byte> payload) noexcept;
    void catchup(detail::cm_batch_context &ctx) noexcept;

    [[nodiscard]] const std::string &id() const noexcept { return id_; }
    [[nodiscard]] detail::seq_num_t message_count() const noexcept { return detail::seq_num_t{ boundaries_.size() }; }
    [[nodiscard]] bool owned_by(std::string_view username) const noexcept { return owner_ == username; }
    [[nodiscard]] std::vector<sn_subscriber> &subscribers() noexcept { return subscribers_; }

    // NOLINTNEXTLINE(modernize-use-nodiscard)
    std::unordered_set<detail::cl_descriptor> assert_consistency() const noexcept;

private:
    std::string id_;
    std::string owner_;

    std::vector<std::byte> stream_;
    std::vector<size_t> boundaries_;
    std::vector<sn_subscriber> subscribers_;
};

} // namespace soupbin::detail
