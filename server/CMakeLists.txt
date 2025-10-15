# ============================================================================
# Options
# ============================================================================
set(SOUPBIN_POLL_MS             1    CACHE STRING "Maximum milliseconds waiting on epoll")
set(SOUPBIN_MAX_CLIENTS         1024 CACHE STRING "Maximum concurrent clients")
set(SOUPBIN_BATCH_SIZE          32   CACHE STRING "Maximum client batch size")
set(SOUPBIN_MAX_PB_NEW_CLIENTS  16   CACHE STRING "Maximum new clients per batch")
set(SOUPBIN_MAX_PB_CLIENT_RECV  1024 CACHE STRING "Maximum bytes per client per batch")

function(validate_uint16 var)
    if(NOT ${var} MATCHES "^[0-9]+$")
        message(FATAL_ERROR "${var} must be a positive integer")
    endif()
    if(${var} LESS 1 OR ${var} GREATER 65535)
        message(FATAL_ERROR "${var} must be between 1 and 65535 (got ${${var}})")
    endif()
endfunction()

validate_uint16(SOUPBIN_POLL_MS)
validate_uint16(SOUPBIN_MAX_CLIENTS)
validate_uint16(SOUPBIN_BATCH_SIZE)
validate_uint16(SOUPBIN_MAX_PB_NEW_CLIENTS)
validate_uint16(SOUPBIN_MAX_PB_CLIENT_RECV)

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
        src/server.cpp
        src/detail/client_manager.cpp
        src/detail/session.cpp
        src/detail/messages.cpp
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

target_compile_definitions(soupbin_server
    PRIVATE
        SOUPBIN_SERVER_BATCH_SIZE=${SOUPBIN_SERVER_BATCH_SIZE}
        SOUPBIN_SERVER_MAX_CLIENTS=${SOUPBIN_SERVER_MAX_CLIENTS}
        SOUPBIN_SERVER_SESSION_TIMEOUT=${SOUPBIN_SERVER_SESSION_TIMEOUT}
        SOUPBIN_SERVER_BUFFER_SIZE=${SOUPBIN_SERVER_BUFFER_SIZE}
)

# ============================================================================
# Tests
# ============================================================================
if(SOUPBIN_BUILD_TESTS)
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
