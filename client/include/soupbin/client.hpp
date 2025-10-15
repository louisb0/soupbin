#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <string>
#include <system_error>

namespace soupbin {

// ============================================================================
// Types.
// ============================================================================

enum class message_type : uint8_t {
    debug,
    unsequenced,
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
    client(const client &) = delete;
    client &operator=(const client &) = delete;
    client(client &&) noexcept;
    client &operator=(client &&) noexcept;
    ~client() noexcept;

    // TODO: What interface if not connected? Exceptions?
    void recv(std::span<std::byte>) noexcept;
    [[nodiscard]] bool try_recv(std::span<std::byte>) noexcept;
    [[nodiscard]] bool send(message_type type, std::span<const std::byte> payload) noexcept;
    bool disconnect() noexcept;

    [[nodiscard]] bool connected() const noexcept;
    [[nodiscard]] const std::string &session_id() const noexcept;
    [[nodiscard]] size_t sequence_num() const noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    [[nodiscard]] explicit client(std::unique_ptr<impl>) noexcept;
    friend std::expected<client, std::error_code> connect(connect_config);
};

[[nodiscard]] std::expected<client, std::error_code> connect(connect_config);

} // namespace soupbin
