#include "soupbin/client.hpp"

#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"
#include "common/messages.hpp"
#include "common/verify.hpp"

#include "client.hpp"

#include <chrono>
#include <iostream>
#include <system_error>
#include <thread>
#include <utility>

namespace soupbin {

// ============================================================================
// Declarations.
// ============================================================================

client::client(std::unique_ptr<impl> pimpl) noexcept : impl_(std::move(pimpl)) {}
client::client(client &&other) noexcept = default;
client &client::operator=(client &&) noexcept = default;
client::~client() noexcept = default;

void client::send(message_type type, std::span<const std::byte> payload) noexcept { impl_->send(type, payload); }
void client::recv(message_type &type, std::span<std::byte> buffer) noexcept { impl_->recv(type, buffer); }
bool client::try_send(message_type type, std::span<const std::byte> payload) noexcept {
    return impl_->try_send(type, payload);
}
bool client::try_recv(message_type &type, std::span<std::byte> buffer) noexcept { return impl_->try_recv(type, buffer); }

bool client::disconnect() noexcept { return impl_->disconnect(); }
bool client::connected() const noexcept { return impl_->connected(); }

const std::string &client::session_id() const noexcept { return impl_->session_id(); }
size_t client::sequence_num() const noexcept { return impl_->sequence_num(); }

// ============================================================================
// Definitions.
// ============================================================================

client::impl::impl(common::valid_fd_t fd, std::string session_id, common::seq_num_t sequence_num)
    : fd_(fd), session_id_(std::move(session_id)), sequence_num_(sequence_num) {
    DEBUG_ASSERT(common::verify_fd(fd_));
    DEBUG_ASSERT(session_id_.length() == common::msg_session_id_len);

    thread_ = std::jthread([this](const std::stop_token &token) { run(token); });
}

void client::impl::send(message_type type, std::span<const std::byte> payload) noexcept {}
void client::impl::recv(message_type &type, std::span<std::byte> buffer) noexcept {}

bool client::impl::try_send(message_type type, std::span<const std::byte> payload) noexcept { return false; }
bool client::impl::try_recv(message_type &type, std::span<std::byte> buffer) noexcept { return false; }

void client::impl::run(const std::stop_token &token) noexcept {
    auto spsc = detail::spsc_ringbuf::create(common::page_size);

    while (!token.stop_requested()) {
        LOG_INFO("tick");
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void client::impl::assert_consistency() const noexcept {}

// ============================================================================
// Factory.
// ============================================================================

[[nodiscard]] std::expected<client, std::error_code> client::connect(connect_config cfg) noexcept {
    return client(std::make_unique<impl>(common::valid_fd_t(0), "1234567890", common::seq_num_t(0)));
}

} // namespace soupbin
