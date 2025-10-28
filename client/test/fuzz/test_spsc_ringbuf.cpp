#include "detail/spsc_ringbuf.hpp"

#include "common/assert.hpp"
#include "common/config.hpp"
#include "common/log.hpp"

#include <chrono>
#include <numeric>
#include <thread>

using namespace soupbin;

constexpr size_t n = 10000000;

int main() {
    static_assert(n / common::page_size >= 1000); // NOLINT
    auto spsc = detail::spsc_ringbuf::create(common::page_size);
    ASSERT(spsc.has_value());

    std::atomic<bool> flag{ false };
    std::jthread producer([&] {
        while (!flag) {
        }

        for (size_t i = 0; i < n; i++) {
            auto *write = reinterpret_cast<size_t *>(spsc->write_prepare(sizeof(i)));
            *write = i;
            spsc->write_commit(sizeof(size_t));
        }
    });

    size_t sum{};
    auto start = std::chrono::steady_clock::now();

    flag = true;
    for (size_t i = 0; i < n; i++) {
        auto read = spsc->read_prepare();
        sum += *reinterpret_cast<const size_t *>(read.data());
        spsc->read_commit(sizeof(size_t));
    }

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

    ASSERT(spsc->read_try_prepare().empty());
    ASSERT(sum == n * (n - 1) / 2);

    LOG_INFO("{} ns/op", duration.count() / n);
}
