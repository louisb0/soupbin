#include <gtest/gtest.h>

#include "detail/client_manager.hpp"
#include "detail/messages.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include "server.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/util.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using namespace soupbin;

TEST(SessionTest, Smoke) {
    // Setup clients.
    std::array<std::byte, 1024> buffer{}; // NOLINT

    int fds1[2], fds2[2]; // NOLINT
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds1), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);

    int flags = fcntl(fds2[1], F_GETFL, 0);
    ASSERT_NE(flags, -1);
    ASSERT_EQ(fcntl(fds2[1], F_SETFL, flags | O_NONBLOCK), 0);

    detail::cl_random_access client1{};
    client1.descriptor.fd = detail::valid_fd_t{ static_cast<uint16_t>(fds1[0]) };
    client1.descriptor.handle = detail::client_handle_t{ 0 };

    detail::cl_random_access client2{};
    client2.descriptor.fd = detail::valid_fd_t{ static_cast<uint16_t>(fds2[0]) };
    client2.descriptor.handle = detail::client_handle_t{ 1 };

    // Setup session.
    detail::session session(generate_alphanumeric(detail::session_id_len), "s1");

    session.subscribe(client1, detail::seq_num_t{ 0 }); // Full replay
    session.assert_consistency();

    const std::vector<std::byte> msg1 = { std::byte{ 0x01 }, std::byte{ 0x02 }, std::byte{ 0x03 } };
    const std::vector<std::byte> msg2 = { std::byte{ 0x04 }, std::byte{ 0x05 } };
    const std::vector<std::byte> msg3 = { std::byte{ 0x06 }, std::byte{ 0x07 }, std::byte{ 0x08 }, std::byte{ 0x09 } };

    // NOTE: append_seq_msg() asserts we have at least one active subscriber, hence the weird subscription ordering.
    session.append_seq_msg(std::span{ msg1 });
    session.append_seq_msg(std::span{ msg2 });
    session.append_seq_msg(std::span{ msg3 });
    session.assert_consistency();
    EXPECT_EQ(detail::ts::get(session.message_count()), 3);

    session.subscribe(client2, detail::seq_num_t{ 3 }); // Up to date, no replay needed
    session.assert_consistency();

    // Catchup.
    detail::cm_batch_context ctx;
    session.catchup(ctx);

    {
        // client1 received all three messages.
        ssize_t read = ::read(fds1[1], buffer.data(), buffer.size());
        EXPECT_GT(read, 0);

        const std::vector<std::vector<std::byte>> expected_payloads = { msg1, msg2, msg3 };
        size_t message_count = 0;
        size_t parsed = 0;

        while (parsed != static_cast<size_t>(read)) {
            const size_t available = static_cast<size_t>(read) - parsed;
            ASSERT_GE(available, sizeof(detail::msg_header));

            const auto *header = reinterpret_cast<const detail::msg_header *>(buffer.data() + parsed);
            EXPECT_EQ(header->type, detail::mt_sequenced);

            const size_t payload_len = ntohs(header->length);
            EXPECT_EQ(payload_len, expected_payloads[message_count].size());

            const size_t message_len = sizeof(detail::msg_header) + payload_len;
            ASSERT_GE(available, message_len);

            std::span<const std::byte> received_payload(buffer.data() + parsed + sizeof(detail::msg_header), payload_len);
            EXPECT_TRUE(std::ranges::equal(received_payload, expected_payloads[message_count]));

            parsed += message_len;
            message_count++;
        }
        EXPECT_EQ(message_count, expected_payloads.size());
    }

    {
        // client2 received nothing.
        ssize_t read = ::read(fds2[1], buffer.data(), buffer.size());
        EXPECT_EQ(read, -1);
        EXPECT_TRUE(errno == EAGAIN || errno == EWOULDBLOCK);
    }

    // Cleanup.
    session.unsubscribe(client1);
    session.unsubscribe(client2);
    session.assert_consistency();

    close(fds1[0]);
    close(fds1[1]);
    close(fds2[0]);
    close(fds2[1]);
}
