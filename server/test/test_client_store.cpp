#include <gtest/gtest.h>

#include "detail/client_manager.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include <algorithm>
#include <bitset>
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
TEST(ClientStore, SmokeTest) {}
// TEST(ClientStore, SmokeTest) {
//     // Setup.
//     int efd = epoll_create1(0);
//     ASSERT_NE(efd, -1);
//
//     int fds1[2], fds2[2], fds3[2];
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds1), 0);
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds3), 0);
//
//     client_manager cstore(valid_fd_t{ static_cast<uint16_t>(efd) }, client_handle_t{ 3 });
//     client_store::bitset to_drop;
//
//     // Add client1 and client2 together.
//     valid_fd_t client_fd1{ static_cast<uint16_t>(fds1[0]) };
//     valid_fd_t client_fd2{ static_cast<uint16_t>(fds2[0]) };
//     valid_fd_t clients_12[] = { client_fd1, client_fd2 };
//     cstore.add(std::span{ clients_12, 2 });
//     (void)cstore.assert_consistency();
//     auto client1_activity = cstore.activity(client_handle_t{ 0 });
//     auto client2_activity = cstore.activity(client_handle_t{ 1 });
//
//     // Add client3.
//     valid_fd_t client_fd3{ static_cast<uint16_t>(fds3[0]) };
//     cstore.add(std::span{ &client_fd3, 1 });
//     (void)cstore.assert_consistency();
//     auto client3_activity = cstore.activity(client_handle_t{ 2 });
//
//     EXPECT_EQ(client2_activity.last_recv, client1_activity.last_recv);
//     EXPECT_GT(client3_activity.last_recv, client2_activity.last_recv);
//     EXPECT_EQ(cstore.size(), 3);
//     EXPECT_TRUE(cstore.full());
//
//     // Send data to all clients.
//     const char data[] = "test";
//     for (auto *fd_pair : { fds1, fds2, fds3 }) {
//         ASSERT_EQ(write(fd_pair[1], data, sizeof(data)), sizeof(data));
//     }
//
//     // Get ready clients.
//     auto [_, ready] = cstore.poll(0);
//     ASSERT_EQ(ready.size(), 3);
//
//     // Remove client1 and client3 together while ready.
//     to_drop.reset();
//     to_drop.set(0).set(2);
//     cstore.remove(to_drop);
//     (void)cstore.assert_consistency();
//     EXPECT_EQ(cstore.size(), 1);
//
//     // Verify remaining client is client2 and ready list updated.
//     auto [__, ready_after] = cstore.poll(0);
//     ASSERT_EQ(ready_after.size(), 1);
//     EXPECT_EQ(ready_after[0]->descriptor.handle, 0);
//     EXPECT_EQ(ready_after[0]->descriptor.fd, client_fd2);
//
//     // Ensure activity info consistency.
//     auto remaining_activity = cstore.activity(client_handle_t{ 0 });
//     EXPECT_EQ(client2_activity.last_recv, remaining_activity.last_recv);
//
//     // Remove client2.
//     to_drop.reset();
//     to_drop.set(0);
//     cstore.remove(to_drop);
//     (void)cstore.assert_consistency();
//     EXPECT_EQ(cstore.size(), 0);
//
//     // Cleanup.
//     for (auto *fd_pair : { fds1, fds2, fds3 }) {
//         close(fd_pair[1]);
//     }
// }
//
// TEST(ClientStore, OrderingProperty) {
//     // Setup.
//     int efd = epoll_create1(0);
//     ASSERT_NE(efd, -1);
//
//     int fds1[2], fds2[2], fds3[2], fds4[2];
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds1), 0);
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds2), 0);
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds3), 0);
//     ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds4), 0);
//
//     client_manager cstore(valid_fd_t{ static_cast<uint16_t>(efd) }, client_handle_t{ 4 });
//     client_store::bitset to_drop;
//
//     session sess1(generate_session_id(), "1"), sess2(generate_session_id(), "2");
//
//     // Set up scenario:
//     // - Client 1 & 3: authed with sess1
//     // - Client 2: authed with sess2
//     // - Client 4: unauthed
//     valid_fd_t client_fd1{ static_cast<uint16_t>(fds1[0]) };
//     valid_fd_t client_fd2{ static_cast<uint16_t>(fds2[0]) };
//     valid_fd_t client_fd3{ static_cast<uint16_t>(fds3[0]) };
//     valid_fd_t client_fd4{ static_cast<uint16_t>(fds4[0]) };
//     valid_fd_t all_clients[] = { client_fd1, client_fd2, client_fd3, client_fd4 };
//     cstore.add(std::span{ all_clients, 4 });
//     (void)cstore.assert_consistency();
//
//     const char data[] = "test";
//     for (auto *fd_pair : { fds1, fds2, fds3, fds4 }) {
//         ASSERT_EQ(write(fd_pair[1], data, sizeof(data)), sizeof(data));
//     }
//
//     auto [authed_before, unauthed_before] = cstore.poll(0);
//     EXPECT_EQ(authed_before.size(), 0);
//     EXPECT_EQ(unauthed_before.size(), 4);
//
//     // Client 1/3 on Session 1, Client 2 on Session 2, Client 4 unauthed
//     sess1.subscribe(*unauthed_before[0], seq_num_t{ 0 });
//     sess1.subscribe(*unauthed_before[2], seq_num_t{ 0 });
//     sess2.subscribe(*unauthed_before[1], seq_num_t{ 0 });
//
//     // Get ready clients.
//     auto [authed, unauthed] = cstore.poll(0);
//
//     EXPECT_EQ(authed.size(), 3);
//     EXPECT_EQ(unauthed.size(), 1);
//
//     // Verify authentication.
//     EXPECT_TRUE(std::all_of(authed.begin(), authed.end(), [](auto *c) { return c->authed(); }));
//     EXPECT_TRUE(std::all_of(unauthed.begin(), unauthed.end(), [](auto *c) { return !c->authed(); }));
//
//     // Verify ordering.
//     for (size_t i = 1; i < authed.size(); ++i) {
//         EXPECT_GE(authed[i - 1]->session, authed[i]->session);
//     }
//
//     // Clean up.
//     to_drop.set();
//     cstore.remove(to_drop);
//     (void)cstore.assert_consistency();
//     EXPECT_EQ(cstore.size(), 0);
//
//     // Cleanup.
//     for (auto *fd_pair : { fds1, fds2, fds3, fds4 }) {
//         close(fd_pair[1]);
//     }
// }
// // NOLINTEND
