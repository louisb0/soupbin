#pragma once

#include <source_location>

#include <spdlog/spdlog.h>

#ifdef SOUPBIN_LOGGING_ENABLED
#define LOG_IMPL(level, msg, ...)                                                                                           \
    do {                                                                                                                    \
        auto loc = std::source_location::current();                                                                         \
        spdlog::level("[{}] " msg, loc.function_name(), ##__VA_ARGS__);                                                     \
    } while (0)
#else
#define LOG_IMPL(level, msg, ...) ((void)0)
#endif

#define LOG_CRITICAL(msg, ...) LOG_IMPL(critical, msg, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) LOG_IMPL(error, msg, ##__VA_ARGS__)
#define LOG_WARN(msg, ...) LOG_IMPL(warn, msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...) LOG_IMPL(info, msg, ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) LOG_IMPL(debug, msg, ##__VA_ARGS__)
