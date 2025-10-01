#include <gtest/gtest.h>

#include "detail/client_store.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace soupbin::detail;

// NOLINTBEGIN
TEST(ClientStore, SmokeTest) {
    // Setup.
    int efd = epoll_create1(0);
    ASSERT_NE(efd, -1);

    int fds1[2], fds2[2], fds3[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds1), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds3), 0);

    client_store cstore(valid_fd_t{ static_cast<uint16_t>(efd) }, client_handle_t{ 3 });

    // Add client1 and client2 together.
    valid_fd_t client_fd1{ static_cast<uint16_t>(fds1[0]) };
    valid_fd_t client_fd2{ static_cast<uint16_t>(fds2[0]) };
    valid_fd_t clients_12[] = { client_fd1, client_fd2 };
    cstore.add(std::span{ clients_12, 2 });
    cstore.assert_consistency();
    auto client1_activity = cstore.activity(client_handle_t{ 0 });
    auto client2_activity = cstore.activity(client_handle_t{ 1 });

    // Add client3.
    valid_fd_t client_fd3{ static_cast<uint16_t>(fds3[0]) };
    cstore.add(std::span{ &client_fd3, 1 });
    cstore.assert_consistency();
    auto client3_activity = cstore.activity(client_handle_t{ 2 });

    EXPECT_EQ(client2_activity.last_recv, client1_activity.last_recv);
    EXPECT_GT(client3_activity.last_recv, client2_activity.last_recv);
    EXPECT_EQ(cstore.size(), 3);
    EXPECT_EQ(cstore.activity().size(), 3);
    EXPECT_TRUE(cstore.full());

    // Send data to all clients.
    const char data[] = "test";
    for (auto *fd_pair : { fds1, fds2, fds3 }) {
        ASSERT_EQ(write(fd_pair[1], data, sizeof(data)), sizeof(data));
    }

    // Get ready clients.
    auto [_, ready] = cstore.ready(0);
    ASSERT_EQ(ready.size(), 3);

    // Remove client1 and client3 together while ready.
    client_handle_t handles_13[] = { client_handle_t{ 0 }, client_handle_t{ 2 } };
    cstore.remove(std::span{ handles_13, 2 });
    cstore.assert_consistency();
    EXPECT_EQ(cstore.size(), 1);
    EXPECT_EQ(cstore.activity().size(), 1);

    // Verify remaining client is client2 and ready list updated.
    auto [__, ready_after] = cstore.ready(0);
    ASSERT_EQ(ready_after.size(), 1);
    EXPECT_EQ(ready_after[0]->handle.get(), 0);
    EXPECT_EQ(ready_after[0]->fd.get(), client_fd2.get());

    // Ensure activity info consistency.
    auto remaining_activity = cstore.activity(client_handle_t{ 0 });
    EXPECT_EQ(client2_activity.last_recv, remaining_activity.last_recv);

    // Remove client2.
    client_handle_t handle2{ 0 };
    cstore.remove(std::span{ &handle2, 1 });
    cstore.assert_consistency();
    EXPECT_EQ(cstore.size(), 0);
    EXPECT_EQ(cstore.activity().size(), 0);

    // Cleanup.
    for (auto *fd_pair : { fds1, fds2, fds3 }) {
        close(fd_pair[1]);
    }
}

TEST(ClientStore, OrderingProperty) {
    // Setup.
    int efd = epoll_create1(0);
    ASSERT_NE(efd, -1);

    int fds1[2], fds2[2], fds3[2], fds4[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds1), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds3), 0);
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds4), 0);

    client_store cstore(valid_fd_t{ static_cast<uint16_t>(efd) }, client_handle_t{ 4 });
    session sess1, sess2;

    // Set up scenario:
    // - Client 1 & 3: authed with sess1
    // - Client 2: authed with sess2
    // - Client 4: unauthed
    valid_fd_t client_fd1{ static_cast<uint16_t>(fds1[0]) };
    valid_fd_t client_fd2{ static_cast<uint16_t>(fds2[0]) };
    valid_fd_t client_fd3{ static_cast<uint16_t>(fds3[0]) };
    valid_fd_t client_fd4{ static_cast<uint16_t>(fds4[0]) };
    valid_fd_t all_clients[] = { client_fd1, client_fd2, client_fd3, client_fd4 };
    cstore.add(std::span{ all_clients, 4 });
    cstore.assert_consistency();

    const char data[] = "test";
    for (auto *fd_pair : { fds1, fds2, fds3, fds4 }) {
        ASSERT_EQ(write(fd_pair[1], data, sizeof(data)), sizeof(data));
    }

    auto [authed_before, unauthed_before] = cstore.ready(0);
    EXPECT_EQ(authed_before.size(), 0);
    EXPECT_EQ(unauthed_before.size(), 4);

    unauthed_before[0]->sess = &sess1; // client1
    unauthed_before[2]->sess = &sess1; // client3
    unauthed_before[1]->sess = &sess2; // client2
    // client4 remains unauthed (sess = nullptr)

    // Get ready clients.
    auto [authed, unauthed] = cstore.ready(0);

    EXPECT_EQ(authed.size(), 3);
    EXPECT_EQ(unauthed.size(), 1);

    // Verify authentication.
    EXPECT_TRUE(std::all_of(authed.begin(), authed.end(), [](auto *c) { return c->authed(); }));
    EXPECT_TRUE(std::all_of(unauthed.begin(), unauthed.end(), [](auto *c) { return !c->authed(); }));

    // Verify ordering.
    for (size_t i = 1; i < authed.size(); ++i) {
        EXPECT_GE(authed[i - 1]->sess, authed[i]->sess);
    }

    // Clean up.
    client_handle_t all_handles[] = {
        client_handle_t{ 0 },
        client_handle_t{ 1 },
        client_handle_t{ 2 },
        client_handle_t{ 3 },
    };
    cstore.remove(std::span{ all_handles, 4 });
    cstore.assert_consistency();
    EXPECT_EQ(cstore.size(), 0);

    // Cleanup.
    for (auto *fd_pair : { fds1, fds2, fds3, fds4 }) {
        close(fd_pair[1]);
    }
}
// NOLINTEND
