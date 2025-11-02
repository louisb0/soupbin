#pragma once

#include "common/log.hpp"

#include <bitset>
#include <cstdint>
#include <functional>
#include <limits>
#include <utility>

#include <type_safe/strong_typedef.hpp>

namespace soupbin::common {
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

struct seq_num_t
    : ts::strong_typedef<seq_num_t, uint64_t>,
      ts::strong_typedef_op::equality_comparison<seq_num_t>,
      ts::strong_typedef_op::relational_comparison<seq_num_t>,
      ts::strong_typedef_op::increment<seq_num_t> {
    using strong_typedef::strong_typedef;
};

// clang-format on
} // namespace soupbin::common

// ============================================================================
// Specialisations.
// ============================================================================

namespace std {
template <>
struct hash<soupbin::common::valid_fd_t> : type_safe::hashable<soupbin::common::valid_fd_t> {};
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
