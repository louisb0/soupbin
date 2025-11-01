#pragma once

#include "common/assert.hpp"

#include <cstdint>
#include <system_error>

#include <netdb.h>

namespace soupbin {

// ============================================================================
// soubpin errors.
// ============================================================================

// NOLINTNEXTLINE(readability-enum-initial-value)
enum class errc : uint8_t {
    setup_hostname_format = 1,
    setup_port_format,
    setup_not_connectable,
    setup_username_format,
    setup_password_format,
    setup_session_id_format,
    setup_sequence_num_format,
    no_such_login,
    no_such_session,
    payload_too_small,
    payload_too_large,
    buffer_too_small,
    invalid_message_type,
    protocol,

    first_ = setup_hostname_format,
    last_ = protocol,
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
        case errc::setup_not_connectable:
            return "no resolved address for the given host and port was connectable";
        case errc::setup_username_format:
            return "username was empty or exceeded maximum length";
        case errc::setup_password_format:
            return "password was empty or exceeded maximum length";
        case errc::setup_session_id_format:
            return "session_id was empty or exceeded maximum length";
        case errc::setup_sequence_num_format:
            return "sequence_num was empty or exceeded maximum length";
        case errc::no_such_login:
            return "login was rejected due to invalid credentials";
        case errc::no_such_session:
            return "login was rejected due to invalid session";
        case errc::payload_too_small:
            return "payload is empty";
        case errc::payload_too_large:
            return "payload exceeded upper bound";
        case errc::buffer_too_small:
            return "buffer does not have enough space for the maximum message size";
        case errc::invalid_message_type:
            return "an invalid message type was provided";
        case errc::protocol:
            return "a protocol violation occured";
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

// ============================================================================
// getaddrinfo() errors.
// ============================================================================

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
