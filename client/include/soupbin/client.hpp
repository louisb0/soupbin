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

enum class message_type : uint8_t {
    none,
    debug,
    unsequenced,
    sequenced,
};

enum class disconnect_reason : uint8_t {
    none,
    logout,
    end_of_session,
    heartbeat,
    abrupt_tcp_disconnect,
    orderly_tcp_disconnect,
    proto_malformed_length,
    proto_malformed_type,
    proto_excessive_length,
    proto_unexpected_type,
};

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

class client {
public:
    static std::expected<client, std::error_code> connect(const connect_config &) noexcept;

    client(const client &) = delete;
    client &operator=(const client &) = delete;
    client(client &&) noexcept;
    client &operator=(client &&) noexcept;
    ~client() noexcept;

    [[nodiscard]] std::error_code send(message_type type, std::span<const std::byte> payload) noexcept;
    [[nodiscard]] std::error_code recv(message_type &type, std::span<std::byte> buffer, size_t &bytes) noexcept;
    [[nodiscard]] std::optional<std::error_code> try_send(message_type type, std::span<const std::byte> payload) noexcept;
    [[nodiscard]] std::optional<std::error_code> try_recv(message_type &type, std::span<std::byte> buffer,
                                                          size_t &bytes) noexcept;

    void disconnect() noexcept;
    [[nodiscard]] bool connected() const noexcept;
    [[nodiscard]] enum disconnect_reason disconnect_reason() const noexcept;

    [[nodiscard]] const std::string &session_id() const noexcept;
    [[nodiscard]] size_t sequence_num() const noexcept;

private:
    class impl;
    std::unique_ptr<impl> impl_;

    [[nodiscard]] explicit client(std::unique_ptr<impl>) noexcept;
};

} // namespace soupbin
