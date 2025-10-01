#include <soupbin/server.hpp>

#include <iostream>

bool handle_auth(std::string_view username, std::string_view password) {
    (void)username;
    return password == "abc";
}

void handle_client_msgs(std::string_view session_id, std::span<soupbin::message_descriptor> descriptors,
                        const soupbin::reply_handler &on_reply) {
    (void)session_id;
    for (const auto &desc : descriptors) {
        std::error_code err = on_reply(soupbin::message_type::unsequenced, { desc.offset, desc.len });
        if (err) {
            std::cerr << "[" << err.category().name() << "]: " << err.message() << '\n';
        }
    }
}

bool handle_tick() { return true; }

int main() {
    auto server = soupbin::make_server({
        .hostname = "localhost",
        .port = "8888",
        .tick_ms = 1,
        .on_auth = handle_auth,
        .on_client_msgs = handle_client_msgs,
        .on_tick = handle_tick,
    });

    if (!server) {
        const auto &err = server.error();
        std::cerr << "[" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    auto err = server->run();
    if (err) {
        std::cerr << "[" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
