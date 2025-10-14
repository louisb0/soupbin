#pragma once

#include <spdlog/spdlog.h>

#ifdef SOUPBIN_LOGGING_ENABLED
#ifndef SOUPBIN_SOURCE_DIR
#error "SOUPBIN_SOURCE_DIR must defined when SOUPBIN_LOGGING_ENABLED is set."
#endif

constexpr const char *strip_source_dir(const char *path) {
    const char *prefix = SOUPBIN_SOURCE_DIR;

    const char *path_ptr = path;
    const char *prefix_ptr = prefix;

    while (*prefix_ptr != '\0' && *path_ptr == *prefix_ptr) {
        ++path_ptr;
        ++prefix_ptr;
    }

    return (*prefix_ptr == '\0') ? path_ptr : path;
}

// TODO: https://github.com/gabime/spdlog/issues/1797
#define LOG_IMPL(level, msg, ...)                                                                                           \
    do {                                                                                                                    \
        spdlog::level("[{}:{}] " msg, strip_source_dir(__FILE__), __LINE__, ##__VA_ARGS__);                                 \
    } while (0)
#else
#define LOG_IMPL(level, msg, ...) ((void)0)
#endif

#define LOG_CRITICAL(msg, ...) LOG_IMPL(critical, msg, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...) LOG_IMPL(error, msg, ##__VA_ARGS__)
#define LOG_WARN(msg, ...) LOG_IMPL(warn, msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...) LOG_IMPL(info, msg, ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...) LOG_IMPL(debug, msg, ##__VA_ARGS__)
