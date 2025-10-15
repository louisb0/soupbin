#pragma once

#include <cassert>
#include <cerrno>

#include <spdlog/spdlog.h>

namespace soupbin::common {

#define PANIC(message, ...)                                                                                                 \
    do {                                                                                                                    \
        spdlog::critical("[{}:{}] Panic: " message, __FILE__, __LINE__, ##__VA_ARGS__);                                     \
        std::abort();                                                                                                       \
    } while (0)

#define ASSERT_UNREACHABLE()                                                                                                \
    do {                                                                                                                    \
        spdlog::critical("[{}:{}] Unreachable location hit.", __FILE__, __LINE__);                                          \
        std::abort();                                                                                                       \
    } while (0)

#define ASSERT(condition)                                                                                                   \
    do {                                                                                                                    \
        if (!(condition)) [[unlikely]] { /* NOLINT(readability-simplify-boolean-expr) */                                    \
            spdlog::critical("[{}:{}] Assertion failed.", __FILE__, __LINE__);                                              \
            std::abort();                                                                                                   \
        }                                                                                                                   \
    } while (0)

#ifdef NDEBUG
#define DEBUG_ASSERT(condition) ((void)0)
#else
#define DEBUG_ASSERT(condition) ASSERT(condition)
#endif

#ifdef NFUZZ
#define FUZZ_UNREACHABLE(condition) ((void)0)
#else
#define FUZZ_UNREACHABLE() ASSERT_UNREACHABLE()
#endif

#if !defined(NFUZZ) && defined(NDEBUG)
#error "Fuzzing requires a debug build."
#endif

} // namespace soupbin::common
