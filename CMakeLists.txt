cmake_minimum_required(VERSION 3.20)
project(soupbin)

option(SOUPBIN_ENABLE_LOGGING "Enable logging" ON)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -Wnon-virtual-dtor")

set(CMAKE_CXX_FLAGS_DEBUG "-g -Og -fsanitize=address,undefined -fsanitize-undefined-trap-on-error -fno-omit-frame-pointer ")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")

set(CMAKE_CXX_FLAGS_PROFILE "-g3 -O3 -DNDEBUG -fno-omit-frame-pointer")
set(CMAKE_EXE_LINKER_FLAGS_PROFILE "")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "")

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-s")
set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "-s")

add_subdirectory(common)
add_subdirectory(server)
add_subdirectory(client)
add_subdirectory(example)
