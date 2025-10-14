# ============================================================================
# Target
# ============================================================================
add_library(soupbin_client STATIC)
add_library(soupbin::client ALIAS soupbin_client)

target_sources(soupbin_client
    PRIVATE
        src/client.cpp
)

target_include_directories(soupbin_client
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(soupbin_client
    PUBLIC
        soupbin::common
)

# ============================================================================
# Tests
# ============================================================================
if(SOUPBIN_BUILD_TESTS)
endif()
