# ============================================================================
# Options
# ============================================================================
set(SOUPBIN_POLL_MS             1    CACHE STRING "Maximum milliseconds waiting on epoll")
set(SOUPBIN_MAX_CLIENTS         1024 CACHE STRING "Maximum concurrent clients")
set(SOUPBIN_BATCH_SIZE          32   CACHE STRING "Maximum client batch size")
set(SOUPBIN_MAX_PB_NEW_CLIENTS  16   CACHE STRING "Maximum new clients per batch")
set(SOUPBIN_MAX_PB_CLIENT_RECV  1024 CACHE STRING "Maximum bytes per client per batch")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/src/detail/config.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/detail/config.hpp
    @ONLY
)

# ============================================================================
# Target
# ============================================================================
add_library(soupbin_server STATIC)
add_library(soupbin::server ALIAS soupbin_server)

target_sources(soupbin_server
    PRIVATE
        src/server_impl.cpp
        src/detail/client_manager.cpp
        src/detail/session.cpp
)

target_include_directories(soupbin_server
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(soupbin_server
    PUBLIC
        soupbin::common
)

# ============================================================================
# Tests
# ============================================================================
if(SOUPBIN_BUILD_UNIT_TESTS)
    add_executable(soupbin_server_tests
        test/test_client_manager.cpp
        test/test_session.cpp
    )

    target_link_libraries(soupbin_server_tests
        PRIVATE
            soupbin::server
            GTest::gtest
            GTest::gtest_main
    )

    target_include_directories(soupbin_server_tests
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_BINARY_DIR}/generated
    )

    gtest_discover_tests(soupbin_server_tests)
endif()
