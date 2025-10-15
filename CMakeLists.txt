cmake_minimum_required(VERSION 3.20)
project(soupbin VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Options
# ============================================================================
option(SOUPBIN_BUILD_TESTS "Build unit tests" ON)
option(SOUPBIN_BUILD_EXAMPLES "Build example programs" ON)
option(SOUPBIN_ENABLE_LOGGING "Enable logging support" ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose: Debug Profile Release" FORCE)
endif()

set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Profile" "Release")

# ============================================================================
# Compiler Flags
# ============================================================================
add_compile_options(-Wall -Wextra -Wshadow -Wnon-virtual-dtor -pedantic)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -Og -fno-omit-frame-pointer)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
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
