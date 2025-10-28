#include <soupbin/server.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>

bool handle_auth(std::string_view username, std::string_view password) {
    (void)username;

    return password == "pass";
}

void handle_client_messages(std::string_view session_id, std::span<soupbin::message_view> views,
                            const soupbin::reply_handler &on_reply) {
    (void)session_id;

    for (const auto &view : views) {
        std::error_code err = on_reply(soupbin::message_type::sequenced, { view.offset, view.len });
        if (err) {
            std::cerr << "[" << err.category().name() << "]: " << err.message() << '\n';
        }
    }
}

int main() {
    auto server = soupbin::server::create({
        .hostname = "localhost",
        .port = "8888",
        .tick = std::chrono::milliseconds(1),
        .on_auth = handle_auth,
        .on_client_messages = handle_client_messages,
    });

    if (!server) {
        const auto &err = server.error();
        std::cerr << "[" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    server->run();

    return EXIT_SUCCESS;
}
