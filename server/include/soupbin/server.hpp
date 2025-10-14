#pragma once

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

// ------------------ types ------------------

enum class message_type : uint8_t {
    debug,
    unsequenced,
    sequenced,
};

struct message_descriptor {
    const std::byte *offset;
    uint8_t len;
    message_type type;
};

// ----------------- config ------------------

using reply_handler = std::function<std::error_code(message_type type, std::span<const std::byte> payload)>;

using auth_handler = std::function<bool(std::string_view username, std::string_view password)>;
using client_msgs_handler = std::function<void(std::string_view session_id, std::span<message_descriptor> descriptors,
                                               const reply_handler &on_reply)>;
using tick_handler = std::function<bool()>;

struct server_config {
    std::string hostname;
    std::string port;
    uint16_t tick_ms;

    auth_handler on_auth;
    client_msgs_handler on_client_msgs;
    tick_handler on_tick;
};

// ----------------- server ------------------

class server {
public:
    server(const server &) = delete;
    server &operator=(const server &) = delete;
    server(server &&) noexcept;
    server &operator=(server &&) noexcept;
    ~server() noexcept;

    void run() noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    [[nodiscard]] explicit server(std::unique_ptr<impl>) noexcept;
    friend std::expected<server, std::error_code> make_server(server_config);
};

[[nodiscard]] std::expected<server, std::error_code> make_server(server_config);

} // namespace soupbin
