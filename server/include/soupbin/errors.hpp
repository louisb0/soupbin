#pragma once

#include "common/assert.hpp"

#include <cstdint>
#include <system_error>

#include <netdb.h>

namespace soupbin {

// ------------------ server -----------------

// NOLINTNEXTLINE(readability-enum-initial-value)
enum class errc : uint8_t {
    setup_hostname_format = 1,
    setup_port_format,
    setup_not_listenable,
    reply_too_large,

    first_ = setup_hostname_format,
    last_ = setup_port_format,
};

struct soupbin_category_t final : std::error_category {
    [[nodiscard]] const char *name() const noexcept override { return "soupbin"; }

    [[nodiscard]] std::string message(int ev) const override {
        ASSERT(ev >= static_cast<int>(errc::first_));
        ASSERT(ev <= static_cast<int>(errc::last_));

        switch (static_cast<errc>(ev)) {
        case errc::setup_hostname_format:
            return "hostname was empty";
        case errc::setup_port_format:
            return "port was empty";
        case errc::setup_not_listenable:
            return "no resolved address for the given host and port wsa listenable";
        case errc::reply_too_large:
            return "reply payload exceeded upper bound: each reply should contain only one higher level message.";
        default:
            return "unknown";
        }
    }
};

inline const std::error_category &soupbin_category() noexcept {
    static soupbin_category_t inst;
    return inst;
}

inline std::error_code make_soupbin_error(errc e) noexcept { return { static_cast<int>(e), soupbin_category() }; }

// --------------- getaddrinfo ---------------

struct gai_category_t final : std::error_category {
    [[nodiscard]] const char *name() const noexcept override { return "getaddrinfo"; }

    [[nodiscard]] std::string message(int ev) const override {
        const char *s = ::gai_strerror(ev);
        if (s == nullptr) {
            return "unknown";
        }

        return s;
    }
};

inline const std::error_category &gai_category() {
    static gai_category_t inst;
    return inst;
}

inline std::error_code make_gai_error(int eai_code) { return { eai_code, gai_category() }; }

} // namespace soupbin
