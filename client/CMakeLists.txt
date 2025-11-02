# ============================================================================
# Options
# ============================================================================
set(SOUPBIN_MAX_SEND_QUEUE      1048576 CACHE STRING "Maximum send queue size in bytes")
set(SOUPBIN_MAX_RECV_QUEUE      1048576 CACHE STRING "Maximum recv queue size in bytes")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/detail/config.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/detail/config.hpp
    @ONLY
)

# ============================================================================
# Target
# ============================================================================
add_library(soupbin_client STATIC)
add_library(soupbin::client ALIAS soupbin_client)

target_sources(soupbin_client
    PRIVATE
        src/client_impl.cpp
        src/detail/spsc_ringbuf.cpp
        src/detail/event_loop.cpp
)

target_include_directories(soupbin_client
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(soupbin_client
    PUBLIC
        soupbin::common
)

# ============================================================================
# Tests
# ============================================================================
if(SOUPBIN_BUILD_TESTS)
    add_executable(soupbin_client_unit_tests
        test/unit/test_spsc_ringbuf.cpp
    )
    target_link_libraries(soupbin_client_unit_tests
        PRIVATE
            soupbin::client
            GTest::gtest
            GTest::gtest_main
    )
    target_include_directories(soupbin_client_unit_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    gtest_discover_tests(soupbin_client_unit_tests)


    add_executable(soupbin_client_fuzz_tests
        test/fuzz/test_spsc_ringbuf.cpp
    )
    target_link_libraries(soupbin_client_fuzz_tests
        PRIVATE
            soupbin::client
    )
    target_include_directories(soupbin_client_fuzz_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
endif()
