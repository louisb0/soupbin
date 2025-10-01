#pragma once

#include <cassert>
#include <source_location>

#include <spdlog/spdlog.h>

#define PANIC(message)                                                                                                      \
    do {                                                                                                                    \
        auto loc = std::source_location::current();                                                                         \
        spdlog::critical("[{}:{}] Panic: {}", loc.function_name(), loc.line(), message);                                    \
        std::abort();                                                                                                       \
    } while (0)

#define ASSERT_UNREACHABLE()                                                                                                \
    do {                                                                                                                    \
        auto loc = std::source_location::current();                                                                         \
        spdlog::critical("[{}:{}] Unreachable location hit.", loc.function_name(), loc.line());                             \
        std::abort();                                                                                                       \
    } while (0)

#define ASSERT(condition)                                                                                                   \
    do {                                                                                                                    \
        if (!(condition)) [[unlikely]] { /* NOLINT(readability-simplify-boolean-expr) */                                    \
            auto loc = std::source_location::current();                                                                     \
            spdlog::critical("[{}:{}] Assertion failed.", loc.function_name(), loc.line());                                 \
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
