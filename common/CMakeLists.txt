# ============================================================================
# Options
# ============================================================================
set(SOUPBIN_CLIENT_HEARTBEAT_SEC 5  CACHE STRING "Client heartbeat interval in seconds")
set(SOUPBIN_SERVER_HEARTBEAT_SEC 15 CACHE STRING "Server heartbeat interval in seconds")

function(validate_uint8 var)
    if(NOT ${var} MATCHES "^[0-9]+$")
        message(FATAL_ERROR "${var} must be a positive integer")
    endif()
    if(${var} LESS 1 OR ${var} GREATER 65535)
        message(FATAL_ERROR "${var} must be between 1 and 255 (got ${${var}})")
    endif()
endfunction()

validate_uint8(SOUPBIN_SERVER_HEARTBEAT_SEC)
validate_uint8(SOUPBIN_CLIENT_HEARTBEAT_SEC)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/common/config.hpp.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/common/config.hpp
    @ONLY
)

# ============================================================================
# Dependencies
# ============================================================================
include(FetchContent)

set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    type_safe
    GIT_REPOSITORY https://github.com/foonathan/type_safe.git
    GIT_TAG v0.2.4
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(type_safe)
set(CMAKE_WARN_DEPRECATED ON CACHE BOOL "" FORCE)

if(SOUPBIN_ENABLE_LOGGING)
    FetchContent_Declare(
        spdlog
        GIT_REPOSITORY https://github.com/gabime/spdlog.git
        GIT_TAG v1.15.3
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(spdlog)
endif()

# ============================================================================
# Target
# ============================================================================
add_library(soupbin_common INTERFACE)
add_library(soupbin::common ALIAS soupbin_common)

target_include_directories(soupbin_common
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_compile_definitions(soupbin_common
    INTERFACE
        SOUPBIN_SERVER_HEARTBEAT_SEC=${SOUPBIN_SERVER_HEARTBEAT_SEC}
        SOUPBIN_CLIENT_HEARTBEAT_SEC=${SOUPBIN_CLIENT_HEARTBEAT_SEC}
)

target_link_libraries(soupbin_common INTERFACE type_safe)
if(SOUPBIN_ENABLE_LOGGING)
    target_link_libraries(soupbin_common INTERFACE spdlog::spdlog)
    target_compile_definitions(soupbin_common INTERFACE
        SOUPBIN_LOGGING_ENABLED
        SOUPBIN_SOURCE_DIR="${CMAKE_SOURCE_DIR}/"
    )
endif()
