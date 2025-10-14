#include <gtest/gtest.h>

#include "detail/client_manager.hpp"
#include "detail/session.hpp"
#include "detail/types.hpp"

#include "common/assert.hpp"
#include "common/log.hpp"
#include "common/util.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <span>
#include <thread>

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace soupbin;

// NOLINTNEXTLINE
class ClientManagerTest : public testing::Test {
    static constexpr size_t buffer_size_ = 1024;

protected:
    // NOLINTBEGIN(*-non-private-*)
    detail::valid_fd_t epoll_{};
    detail::valid_fd_t listener_{};
    uint16_t port_{};
    // NOLINTEND(*-non-private-*)

    ClientManagerTest() noexcept {
        int epoll_fd = epoll_create1(0);
        ASSERT(epoll_fd != -1);
        epoll_ = detail::valid_fd_t(epoll_fd);

        int listener_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT(listener_fd != -1);

        int opt = 1;
        ASSERT(setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;

        ASSERT(bind(listener_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
        ASSERT(listen(listener_fd, 10) == 0);

        socklen_t addr_len = sizeof(addr);
        ASSERT(getsockname(listener_fd, reinterpret_cast<sockaddr *>(&addr), &addr_len) == 0);
        port_ = ntohs(addr.sin_port);

        listener_ = detail::valid_fd_t(listener_fd);
    }

    ~ClientManagerTest() override {
        close(detail::ts::get(epoll_));
        close(detail::ts::get(listener_));
    }

    [[nodiscard]] int connect_one() const noexcept {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT(fd != -1);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(port_);

        int result = connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
        ASSERT(result == 0 || errno == EINPROGRESS);

        return fd;
    }

    static void send_bytes(int fd, size_t bytes) noexcept {
        static std::array<std::byte, buffer_size_> buffer{};
        ssize_t sent = write(fd, buffer.data(), std::min(bytes, buffer_size_));
        ASSERT(sent == static_cast<ssize_t>(std::min(bytes, buffer_size_)));
    }

    static size_t drain(int fd) noexcept {
        static std::array<std::byte, buffer_size_> buffer{};

        size_t read = 0;
        while (read != buffer_size_) {
            ssize_t received = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
            if (received == -1) {
                if (errno == EINTR) {
                    continue;
                }

                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }

                PANIC("unexpected error: {}", std::strerror(errno));
            }

            if (received == 0) {
                break;
            }

            ASSERT(read <= buffer_size_);
            read += received;
        }

        return read;
    }
};

TEST_F(ClientManagerTest, Smoke) {
    // Setup.
    detail::client_manager cmgr(epoll_, listener_);

    int cfd1 = connect_one();
    int cfd2 = connect_one();
    EXPECT_EQ(cmgr.onboard(detail::client_count_t(2)), 2);
    EXPECT_EQ(cmgr.size(), 2);

    send_bytes(cfd1, 1);
    send_bytes(cfd2, 1);

    // Two unauthenticated clients with data.
    auto ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 2);
    EXPECT_EQ(ctx.authed().size(), 0);
    EXPECT_EQ(ctx.unauthed().size(), 2);
    EXPECT_EQ(cmgr.size(), 2);

    cmgr.process(ctx);
    cmgr.assert_consistency();

    // One unauthenticated client with data.
    drain(detail::ts::get(ctx.all().front()->descriptor.fd));

    ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 1);
    EXPECT_EQ(ctx.authed().size(), 0);
    EXPECT_EQ(ctx.unauthed().size(), 1);
    EXPECT_EQ(cmgr.size(), 2);

    // Remove unauthenticated client with data.
    ctx.mark_drop(ctx.all().front()->descriptor.handle, detail::cm_batch_context::drop_reason::graceful_disconnect);
    cmgr.process(ctx);
    cmgr.assert_consistency();

    ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 0);
    EXPECT_EQ(ctx.authed().size(), 0);
    EXPECT_EQ(ctx.unauthed().size(), 0);
    EXPECT_EQ(cmgr.size(), 1);

    // Remove last client.
    ctx.mark_drop(detail::client_handle_t(0), detail::cm_batch_context::drop_reason::graceful_disconnect);
    cmgr.process(ctx);
    cmgr.assert_consistency();

    EXPECT_EQ(cmgr.size(), 0);

    // Cleanup.
    close(cfd1);
    close(cfd2);
}

TEST_F(ClientManagerTest, Ordering) {
    // Setup.
    detail::client_manager cmgr(epoll_, listener_);

    int cfd1 = connect_one();
    int cfd2 = connect_one();
    int cfd3 = connect_one();
    int cfd4 = connect_one();
    EXPECT_EQ(cmgr.onboard(detail::client_count_t(4)), 4);
    EXPECT_EQ(cmgr.size(), 4);

    send_bytes(cfd1, 1);
    send_bytes(cfd3, 1); // NOTE: Attempts to avoid accidental session grouping.
    send_bytes(cfd2, 1);
    send_bytes(cfd4, 1);

    LOG_INFO("1");
    auto ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 4);
    EXPECT_EQ(ctx.authed().size(), 0);
    EXPECT_EQ(ctx.unauthed().size(), 4);

    detail::session session1(generate_alphanumeric(detail::session_id_len), "s1");
    session1.subscribe(*ctx.all()[0], detail::seq_num_t(0));
    session1.subscribe(*ctx.all()[1], detail::seq_num_t(0));

    detail::session session2(generate_alphanumeric(detail::session_id_len), "s2");
    session2.subscribe(*ctx.all()[2], detail::seq_num_t(0));

    cmgr.process(ctx);
    cmgr.assert_consistency();

    // Four clients with data - three authenticated, one unauthenticated.
    ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 4);
    EXPECT_EQ(ctx.authed().size(), 3);
    EXPECT_EQ(ctx.unauthed().size(), 1);

    // Session grouping and continuity.
    EXPECT_EQ(ctx.authed().data(), ctx.all().data());
    EXPECT_EQ(ctx.authed().data() + ctx.authed().size(), ctx.unauthed().data());

    if (ctx.all()[0]->session == ctx.all()[1]->session) {
        EXPECT_NE(ctx.all()[1], ctx.all()[2]);
    } else if (ctx.all()[1]->session == ctx.all()[2]->session) {
        EXPECT_NE(ctx.all()[0], ctx.all()[1]);
    } else {
        EXPECT_TRUE(false);
    }
    EXPECT_EQ(ctx.all()[3]->session, nullptr);

    cmgr.process(ctx);
    cmgr.assert_consistency();

    // Cleanup.
    close(cfd1);
    close(cfd2);
    close(cfd3);
    close(cfd4);
}

TEST_F(ClientManagerTest, DropHandleManagement) {
    // Setup.
    detail::client_manager cmgr(epoll_, listener_);

    int cfd1 = connect_one();
    int cfd2 = connect_one();
    int cfd3 = connect_one();
    EXPECT_EQ(cmgr.onboard(detail::client_count_t(3)), 3);
    EXPECT_EQ(cmgr.size(), 3);

    send_bytes(cfd1, 1);
    send_bytes(cfd2, 1);
    send_bytes(cfd3, 1);

    auto ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 3);
    EXPECT_EQ(ctx.authed().size(), 0);
    EXPECT_EQ(ctx.unauthed().size(), 3);

    detail::session session(generate_alphanumeric(detail::session_id_len), "s1");
    std::ranges::for_each(ctx.all(), [&session](auto *cl) { session.subscribe(*cl, detail::seq_num_t(0)); });

    cmgr.process(ctx);
    cmgr.assert_consistency();

    // Three authenticated clients with data.
    ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 3);
    EXPECT_EQ(ctx.authed().size(), 3);
    EXPECT_EQ(ctx.unauthed().size(), 0);

    // Drop first client.
    std::array<detail::cl_descriptor, 3> cl_initial{};
    std::ranges::transform(ctx.all(), cl_initial.begin(), [](const auto *cl) { return cl->descriptor; });
    std::ranges::sort(cl_initial, {}, &detail::cl_descriptor::handle);

    ctx.mark_drop(detail::client_handle_t(0), detail::cm_batch_context::drop_reason::graceful_disconnect);
    cmgr.process(ctx);
    cmgr.assert_consistency();

    ctx = cmgr.poll(std::chrono::milliseconds(0));
    EXPECT_EQ(ctx.all().size(), 2);
    EXPECT_EQ(ctx.authed().size(), 2);
    EXPECT_EQ(ctx.unauthed().size(), 0);

    // Dropped file descriptor removed, other two present.
    EXPECT_TRUE(std::ranges::none_of(ctx.all(), [&](const auto *cl) { return cl->descriptor.fd == cl_initial[0].fd; }));
    EXPECT_TRUE(std::ranges::any_of(ctx.all(), [&](const auto *cl) { return cl->descriptor.fd == cl_initial[1].fd; }));
    EXPECT_TRUE(std::ranges::any_of(ctx.all(), [&](const auto *cl) { return cl->descriptor.fd == cl_initial[2].fd; }));

    // Handles adjusted within store and session.
    std::array<detail::cl_descriptor, 2> cl_after{};
    std::ranges::transform(ctx.all(), cl_after.begin(), [](const auto *cl) { return cl->descriptor; });
    std::ranges::sort(cl_after, {}, &detail::cl_descriptor::handle);

    for (size_t i = 0; i < cl_after.size(); i++) {
        EXPECT_EQ(cl_after[i].handle, i);
    }

    for (const auto &cl : cl_after) {
        EXPECT_TRUE(std::ranges::any_of(session.subscribers(), [cl](const auto &sub) { return sub.descriptor == cl; }));
    }

    cmgr.process(ctx);
    cmgr.assert_consistency();

    // Cleanup.
    close(cfd1);
    close(cfd2);
    close(cfd3);
}
