#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>

namespace soupbin {

// ============================================================================
// Types.
// ============================================================================

enum class message_type : uint8_t {
    none,

    debug,
    unsequenced,
    sequenced,
};

// ============================================================================
// Config.
// ============================================================================

static constexpr const char *new_session = " ";
static constexpr const char *sequence_start = "0";

struct connect_config {
    std::string hostname;
    std::string port;
    std::string username;
    std::string password;
    std::string session_id = new_session;
    std::string sequence_num = sequence_start;
};

// ============================================================================
// Client.
// ============================================================================

class client {
public:
    static std::expected<client, std::error_code> connect(const connect_config &) noexcept;

    client(const client &) = delete;
    client &operator=(const client &) = delete;
    client(client &&) noexcept;
    client &operator=(client &&) noexcept;
    ~client() noexcept;

    std::error_code send(message_type type, std::span<const std::byte> payload) noexcept;
    std::error_code recv(message_type &type, std::span<std::byte> buffer, size_t &bytes) noexcept;
    [[nodiscard]] std::optional<std::error_code> try_send(message_type type, std::span<const std::byte> payload) noexcept;
    [[nodiscard]] std::optional<std::error_code> try_recv(message_type &type, std::span<std::byte> buffer,
                                                          size_t &bytes) noexcept;

    bool disconnect() noexcept;
    [[nodiscard]] bool connected() const noexcept;

    [[nodiscard]] std::error_code error() const noexcept;
    [[nodiscard]] const std::string &session_id() const noexcept;
    [[nodiscard]] size_t sequence_num() const noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    [[nodiscard]] explicit client(std::unique_ptr<impl>) noexcept;
};

} // namespace soupbin
