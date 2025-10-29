#pragma once

#include <algorithm>
#include <cstddef>
#include <random>
#include <string>

#include <unistd.h>

namespace soupbin::common {

inline std::string generate_alphanumeric(size_t length) {
    static constexpr char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz"; // NOLINT(*-avoid-c-arrays)

    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    static auto gen = std::mt19937{ std::random_device{}() };

    std::string result(length, '\0');
    std::generate_n(result.begin(), length, [&]() { return charset[dis(gen)]; });

    return result;
}

inline void preserving_close(int fd) noexcept {
    int saved = errno;
    close(fd);
    errno = saved;
}

} // namespace soupbin::common
