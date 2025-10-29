#include <gtest/gtest.h>

#include "detail/spsc_ringbuf.hpp"

#include "common/config.hpp"

#include <cstdlib>
#include <expected>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <utility>

using namespace soupbin;

TEST(SPSCRingbufTest, Smoke) {
    auto expected_spsc = detail::spsc_ringbuf::create(common::page_size);
    ASSERT_TRUE(expected_spsc.has_value());
    auto spsc = std::move(*expected_spsc);

    // Initial conditions.
    ASSERT_TRUE(spsc->read_try_prepare().empty());
    ASSERT_NE(spsc->write_try_prepare(common::page_size), nullptr);

    // Write a size_t.
    auto *write = reinterpret_cast<size_t *>(spsc->write_prepare(common::page_size));
    new (write) size_t(123); // NOLINT
    spsc->write_commit(sizeof(*write));

    ASSERT_EQ(spsc->write_try_prepare(common::page_size), nullptr);
    ASSERT_EQ(reinterpret_cast<const size_t *>(spsc->write_try_prepare(1)), write + 1);

    // Read the size_t.
    auto read = spsc->read_prepare();
    ASSERT_FALSE(spsc->read_prepare().empty());
    ASSERT_EQ(read.size(), sizeof(*write));
    ASSERT_EQ(reinterpret_cast<const size_t *>(read.data()), write);
    ASSERT_EQ(*reinterpret_cast<const size_t *>(read.data()), 123);
    spsc->read_commit(read.size());

    ASSERT_TRUE(spsc->read_try_prepare().empty());
    ASSERT_NE(spsc->write_try_prepare(common::page_size), nullptr);
}
