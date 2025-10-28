#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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

struct message_view {
    const std::byte *offset;
    uint8_t len;
    message_type type;
};

// ============================================================================
// Config.
// ============================================================================

using reply_handler = std::function<std::error_code(message_type type, std::span<const std::byte> payload)>;

using auth_handler = std::function<bool(std::string_view username, std::string_view password)>;
using client_messages_handler =
    std::function<void(std::string_view session_id, std::span<message_view> messages, const reply_handler &on_reply)>;
using tick_handler = std::function<bool()>;

struct server_config {
    std::string hostname;
    std::string port;
    std::chrono::milliseconds tick;

    auth_handler on_auth;
    client_messages_handler on_client_messages;
    tick_handler on_tick = []() { return true; };
};

// ============================================================================
// Server.
// ============================================================================

class server {
public:
    server(const server &) = delete;
    server &operator=(const server &) = delete;
    server(server &&) noexcept;
    server &operator=(server &&) noexcept;
    ~server() noexcept;

    static std::expected<server, std::error_code> create(server_config) noexcept;

    void run() noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    [[nodiscard]] explicit server(std::unique_ptr<impl>) noexcept;
};

} // namespace soupbin
