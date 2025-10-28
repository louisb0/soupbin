#include <soupbin/client.hpp>

#include <array>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <system_error>

#include <unistd.h>

int main() {
    auto client = soupbin::client::connect({
        .hostname = "localhost",
        .port = "8888",
        .username = "user",
        .password = "pass",
    });

    if (!client) {
        const auto &err = client.error();
        std::cout << "Could not connect - [" << err.category().name() << "]: " << err.message() << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Session ID: " << client->session_id() << '\n';
    std::cout << "Sequence num: " << client->sequence_num() << '\n';

    for (int i = 0; i < 5; i++) {           // NOLINT
        std::array<std::byte, 1024> buffer; // NOLINT
        soupbin::message_type type{};

        while (client->try_recv(type, buffer)) {
            auto content = std::string_view(reinterpret_cast<const char *>(buffer.data()), sizeof(buffer));
            std::cout << "Received: " << content << "\n";
        }

        auto msg = std::as_bytes(std::span("Ping!"));
        if (!client->try_send(soupbin::message_type::unsequenced, msg)) {
            std::cout << "Could not send message\n";
            break;
        }

        sleep(1);
    }

    client->disconnect();

    std::cout << "Press Enter to exit...";
    std::cin.get();
}
