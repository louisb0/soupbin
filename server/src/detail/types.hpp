#pragma once

#include "detail/config.hpp"

#include "common/log.hpp"
#include "common/types.hpp"

#include <bitset>
#include <cstdint>
#include <functional>
#include <limits>
#include <utility>

namespace soupbin::detail {

// ============================================================================
// Strong types.
// ============================================================================
// clang-format off

struct client_handle_t
    : common::ts::strong_typedef<client_handle_t, uint16_t>,
      common::ts::strong_typedef_op::output_operator<client_handle_t>,
      common::ts::strong_typedef_op::equality_comparison<client_handle_t>,
      common::ts::strong_typedef_op::mixed_equality_comparison<client_handle_t, size_t>,
      common::ts::strong_typedef_op::relational_comparison<client_handle_t>,
      common::ts::strong_typedef_op::mixed_relational_comparison<client_handle_t, size_t> {
    using strong_typedef::strong_typedef;
};
static_assert(detail::max_clients <= std::numeric_limits<common::ts::underlying_type<client_handle_t>>::max());

struct client_count_t
    : common::ts::strong_typedef<client_count_t, common::ts::underlying_type<client_handle_t>>,
      common::ts::strong_typedef_op::mixed_equality_comparison<client_count_t, size_t>,
      common::ts::strong_typedef_op::mixed_relational_comparison<client_count_t, size_t> {
    using strong_typedef::strong_typedef;
};
static_assert(std::is_same_v<common::ts::underlying_type<client_count_t>, common::ts::underlying_type<client_handle_t>>);

// clang-format on
} // namespace soupbin::detail

// ============================================================================
// Specialisations.
// ============================================================================

namespace std {
template <>
struct hash<soupbin::detail::client_handle_t> : type_safe::hashable<soupbin::detail::client_handle_t> {};
} // namespace std
