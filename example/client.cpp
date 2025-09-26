#include <soupbin/client.hpp>

#include <iostream>

int main() {
    std::cout << soupbin::make_client() << '\n';
    return 0;
}
