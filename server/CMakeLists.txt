add_library(soupbinserver STATIC)

target_sources(soupbinserver PRIVATE
    src/server.cpp
)

target_include_directories(soupbinserver
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
