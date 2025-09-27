#include <gtest/gtest.h>

#include "client_store.hpp"
#include "types.hpp"

#include <cstdint>
#include <span>
#include <string>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace soupbin;

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
    auto client1_activity = cstore.activity_info(client_handle_t{ 0 });
    auto client2_activity = cstore.activity_info(client_handle_t{ 1 });

    // Add client3.
    valid_fd_t client_fd3{ static_cast<uint16_t>(fds3[0]) };
    cstore.add(std::span{ &client_fd3, 1 });
    cstore.assert_consistency();
    auto client3_activity = cstore.activity_info(client_handle_t{ 2 });

    EXPECT_EQ(client2_activity.last_recv, client1_activity.last_recv);
    EXPECT_GT(client3_activity.last_recv, client2_activity.last_recv);
    EXPECT_EQ(cstore.size(), 3);
    EXPECT_EQ(cstore.activity().size(), 3);
    EXPECT_TRUE(cstore.full());

    // Send data to all clients.
    const char data[] = "test";
    ASSERT_EQ(write(fds1[1], data, sizeof(data)), sizeof(data));
    ASSERT_EQ(write(fds2[1], data, sizeof(data)), sizeof(data));
    ASSERT_EQ(write(fds3[1], data, sizeof(data)), sizeof(data));

    // Get ready clients.
    auto ready = cstore.ready(0);
    ASSERT_EQ(ready.size(), 3);

    // Remove client1 and client3 together while ready.
    client_handle_t handles_13[] = { client_handle_t{ 0 }, client_handle_t{ 2 } };
    cstore.remove(std::span{ handles_13, 2 });
    cstore.assert_consistency();
    EXPECT_EQ(cstore.size(), 1);
    EXPECT_EQ(cstore.activity().size(), 1);

    // Verify remaining client is client2 and ready list updated.
    auto ready_after = cstore.ready(0);
    ASSERT_EQ(ready_after.size(), 1);
    EXPECT_EQ(ready_after[0]->handle.get(), 0);
    EXPECT_EQ(ready_after[0]->fd.get(), client_fd2.get());

    // Ensure activity info consistency.
    auto remaining_activity = cstore.activity_info(client_handle_t{ 0 });
    EXPECT_EQ(client2_activity.last_recv, remaining_activity.last_recv);

    // Remove client2.
    client_handle_t handle2{ 0 };
    cstore.remove(std::span{ &handle2, 1 });
    cstore.assert_consistency();
    EXPECT_EQ(cstore.size(), 0);
    EXPECT_EQ(cstore.activity().size(), 0);

    // Cleanup.
    close(fds1[1]);
    close(fds2[1]);
    close(fds3[1]);
}
// NOLINTEND
