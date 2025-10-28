cmake_minimum_required(VERSION 3.20)
project(soupbin VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Options
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose: Debug Profile Release" FORCE)
endif()

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Profile" "Release")

option(SOUPBIN_BUILD_EXAMPLES "Build example programs" ON)
option(SOUPBIN_ENABLE_LOGGING "Enable logging support" ON)
option(SOUPBIN_BUILD_TESTS "Build tests" ON)
option(SOUPBIN_ENABLE_TSAN "Enable Thread Sanitizer" OFF)
option(SOUPBIN_ENABLE_ASAN "Enable Address Sanitizer" ON)

message(STATUS "========================================")
message(STATUS "Build examples:     ${SOUPBIN_BUILD_EXAMPLES}")
message(STATUS "Enable logging:     ${SOUPBIN_ENABLE_LOGGING}")
message(STATUS "Build tests:        ${SOUPBIN_BUILD_TESTS}")
message(STATUS "Thread Sanitizer:   ${SOUPBIN_ENABLE_TSAN}")
message(STATUS "Address Sanitizer:  ${SOUPBIN_ENABLE_ASAN}")
message(STATUS "========================================")

if(SOUPBIN_ENABLE_TSAN AND SOUPBIN_ENABLE_ASAN)
    message(FATAL_ERROR "Cannot enable both TSAN and ASAN.")
endif()

# ============================================================================
# Compiler Flags
# ============================================================================
add_compile_options(-Wall -Wextra -Wshadow -Wnon-virtual-dtor -pedantic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -Og -fno-omit-frame-pointer)

    if(SOUPBIN_ENABLE_TSAN)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    elseif(SOUPBIN_ENABLE_ASAN)
        add_compile_options(-fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "Profile")
    add_compile_options(-g3 -O3 -fno-omit-frame-pointer)
    add_compile_definitions(NFUZZ)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3)
    add_link_options(-s)
    add_compile_definitions(NFUZZ)
endif()

# ============================================================================
# Dependencies
# ============================================================================
if(SOUPBIN_BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    include(GoogleTest)
endif()

# ============================================================================
# Targets
# ============================================================================
add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)

if(SOUPBIN_BUILD_EXAMPLES)
    add_subdirectory(example)
endif()
