#pragma once

#include "detail/config.hpp"

#include "common/log.hpp"

#include <bitset>
#include <cstdint>
#include <functional>
#include <limits>
#include <utility>

#include <type_safe/strong_typedef.hpp>

namespace soupbin::detail {
namespace ts = type_safe;

// ============================================================================
// Strong types.
// ============================================================================
// clang-format off

struct valid_fd_t
    : ts::strong_typedef<valid_fd_t, uint16_t>,
      ts::strong_typedef_op::output_operator<valid_fd_t>,
      ts::strong_typedef_op::equality_comparison<valid_fd_t> {
    using strong_typedef::strong_typedef;
};

struct client_handle_t
    : ts::strong_typedef<client_handle_t, uint16_t>,
      ts::strong_typedef_op::output_operator<client_handle_t>,
      ts::strong_typedef_op::equality_comparison<client_handle_t>,
      ts::strong_typedef_op::mixed_equality_comparison<client_handle_t, size_t>,
      ts::strong_typedef_op::relational_comparison<client_handle_t>,
      ts::strong_typedef_op::mixed_relational_comparison<client_handle_t, size_t> {
    using strong_typedef::strong_typedef;
};
static_assert(detail::max_clients <= std::numeric_limits<ts::underlying_type<client_handle_t>>::max());

struct client_count_t
    : ts::strong_typedef<client_count_t, ts::underlying_type<client_handle_t>>,
      ts::strong_typedef_op::mixed_equality_comparison<client_count_t, size_t>,
      ts::strong_typedef_op::mixed_relational_comparison<client_count_t, size_t> {
    using strong_typedef::strong_typedef;
};
static_assert(std::is_same_v<ts::underlying_type<client_count_t>, ts::underlying_type<client_handle_t>>);

struct seq_num_t
    : ts::strong_typedef<seq_num_t, uint64_t>,
      ts::strong_typedef_op::equality_comparison<seq_num_t>,
      ts::strong_typedef_op::relational_comparison<seq_num_t> {
    using strong_typedef::strong_typedef;
};

// clang-format on
} // namespace soupbin::detail

// ============================================================================
// Specialisations.
// ============================================================================

namespace std {
template <>
struct hash<soupbin::detail::valid_fd_t> : type_safe::hashable<soupbin::detail::valid_fd_t> {};

template <>
struct hash<soupbin::detail::client_handle_t> : type_safe::hashable<soupbin::detail::client_handle_t> {};
} // namespace std

namespace fmt {
template <typename T>
    requires type_safe::is_strong_typedef<T>::value
struct formatter<T, char> : formatter<type_safe::underlying_type<T>> {
    auto format(const T &value, format_context &ctx) const {
        return formatter<type_safe::underlying_type<T>>::format(type_safe::get(value), ctx);
    }
};
} // namespace fmt
