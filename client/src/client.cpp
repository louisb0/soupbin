#include "soupbin/client.hpp"

#include "client.hpp"

#include <system_error>
#include <utility>

namespace soupbin {

// ============================================================================
// Declarations.
// ============================================================================

client::client(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
client::client(client &&other) noexcept = default;
client &client::operator=(client &&) noexcept = default;
client::~client() noexcept = default;

void client::recv(std::span<std::byte> buffer) noexcept { impl_->recv(buffer); }
bool client::try_recv(std::span<std::byte> buffer) noexcept { return impl_->try_recv(buffer); }
bool client::send(message_type type, std::span<const std::byte> payload) noexcept { return impl_->send(type, payload); }

void client::disconnect() noexcept { impl_->disconnect(); }
bool client::connected() const noexcept { return impl_->connected(); }

const std::string &client::session_id() const noexcept { return impl_->session_id(); }
size_t client::sequence_num() const noexcept { return impl_->sequence_num(); }

// ============================================================================
// Definitions.
// ============================================================================

client::impl::impl() noexcept {}

void client::impl::recv(std::span<std::byte>) noexcept {}

bool client::impl::try_recv(std::span<std::byte>) noexcept { return false; }

bool client::impl::send(message_type type, std::span<const std::byte> payload) noexcept { return false; }

void client::impl::disconnect() noexcept {}

void client::impl::assert_consistency() const noexcept {}

// ============================================================================
// Factory.
// ============================================================================

[[nodiscard]] std::expected<client, std::error_code> connect(connect_config cfg) {
    return std::unexpected(std::error_code{});
}

} // namespace soupbin
