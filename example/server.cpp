#include <soupbin/server.hpp>

#include <iostream>

int main() {
    std::cout << soupbin::make_server() << '\n';
    return 0;
}
