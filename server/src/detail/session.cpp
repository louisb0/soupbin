#include "detail/session.hpp"

#include "detail/client_manager.hpp"
#include "detail/config.hpp"
#include "detail/messages.hpp"
#include "detail/network.hpp"
#include "detail/types.hpp"
#include "detail/verify.hpp"

#include "server.hpp"

#include "common/assert.hpp"

#include <algorithm>
#include <ranges>
#include <string>
#include <unordered_set>
#include <utility>

#include <arpa/inet.h>

namespace soupbin::detail {

session::session(std::string id, std::string owner) noexcept : id_(std::move(id)), owner_(std::move(owner)) {
    DEBUG_ASSERT(id_.size() == detail::session_id_len);
    DEBUG_ASSERT(owner_.size() <= detail::username_len);
    DEBUG_ASSERT(!owner_.empty());
}

void session::subscribe(detail::cl_random_access &client, detail::seq_num_t from) noexcept {
    DEBUG_ASSERT(from <= message_count());
    DEBUG_ASSERT(!client.authed());
    DEBUG_ASSERT(!std::ranges::contains(subscribers_, client.descriptor, &detail::sn_subscriber::descriptor));

    subscribers_.emplace_back(client.descriptor, 0, from);
    client.session = this;
}

void session::unsubscribe(detail::cl_random_access &client) noexcept {
    DEBUG_ASSERT(client.authed());
    DEBUG_ASSERT(client.session == this);

    auto it = std::ranges::find(subscribers_, client.descriptor, &detail::sn_subscriber::descriptor);
    DEBUG_ASSERT(it != subscribers_.end());
    subscribers_.erase(it);

    client.session = nullptr;
}

void session::append_seq_msg(std::span<const std::byte> payload) noexcept {
    DEBUG_ASSERT(!payload.empty());
    DEBUG_ASSERT(payload.size() <= detail::max_payload_size);
    DEBUG_ASSERT(!subscribers_.empty());

    const detail::msg_header header{
        .length = htons(static_cast<uint16_t>(payload.size())),
        .type = detail::mt_sequenced,
    };

    boundaries_.emplace_back(stream_.size());

    auto header_bytes = std::as_bytes(std::span{ &header, 1 });
    stream_.insert(stream_.end(), header_bytes.begin(), header_bytes.end());
    stream_.insert(stream_.end(), payload.begin(), payload.end());
}

void session::catchup(detail::cm_batch_context &ctx) noexcept {
    DEBUG_ASSERT(!subscribers_.empty());

    for (auto &sub : subscribers_) {
        if (ctx.dropped(sub.descriptor.handle)) {
            continue;
        }

        if (sub.seq_num == message_count()) {
            continue;
        }

        const size_t start = boundaries_[detail::ts::get(sub.seq_num)];
        const size_t end = stream_.size();

        if (auto failed = detail::send_all(sub.descriptor, &stream_[start], end - start)) {
            ctx.mark_drop(sub.descriptor.handle, *failed);
            continue;
        }

        ctx.mark_sent(sub.descriptor.handle);
        sub.seq_num = message_count();
    }
}

std::unordered_set<detail::cl_descriptor> session::assert_consistency() const noexcept {
#ifndef NDEBUG
    DEBUG_ASSERT(id_.size() == detail::session_id_len);
    DEBUG_ASSERT(owner_.length() <= detail::username_len);
    DEBUG_ASSERT(!owner_.empty());

    // ----------------------------------------
    // (1) Unique and valid subscribers.
    // ----------------------------------------
    std::unordered_set<detail::cl_descriptor> seen;
    for (const auto &sub : subscribers_) {
        DEBUG_ASSERT(sub.seq_num <= message_count());

        DEBUG_ASSERT(detail::verify_fd(sub.descriptor.fd));
        DEBUG_ASSERT(!seen.contains(sub.descriptor));
        seen.insert(sub.descriptor);
    }

    // ----------------------------------------
    // (2) Stream-boundary alignment.
    // ----------------------------------------
    const std::byte *buf = stream_.data();
    const size_t buf_len = stream_.size();

    size_t message_count = 0;
    size_t parsed = 0;
    while (parsed != buf_len) {
        DEBUG_ASSERT(boundaries_[message_count] == parsed);

        const size_t available = buf_len - parsed;
        DEBUG_ASSERT(available > sizeof(detail::msg_header));

        const auto *header = reinterpret_cast<const detail::msg_header *>(buf + parsed);
        DEBUG_ASSERT(header->type == detail::mt_sequenced);

        const size_t payload_len = ntohs(header->length);
        DEBUG_ASSERT(payload_len <= detail::max_payload_size);

        const size_t message_len = sizeof(detail::msg_header) + payload_len;
        DEBUG_ASSERT(available >= message_len);

        parsed += message_len;
        message_count++;
    }

    // ----------------------------------------
    // (3) Boundary-stream alignment.
    // ----------------------------------------
    DEBUG_ASSERT(boundaries_.size() == message_count);
    DEBUG_ASSERT(boundaries_.empty() || boundaries_[0] == 0);

    for (size_t i = 1; i < boundaries_.size(); i++) {
        DEBUG_ASSERT(boundaries_[i - 1] < boundaries_[i]);
        DEBUG_ASSERT(boundaries_[i] - boundaries_[i - 1] > sizeof(detail::msg_header)); // TODO: Minimum message size.
    }

    return seen;
#else
    return {};
#endif
}

} // namespace soupbin::detail
