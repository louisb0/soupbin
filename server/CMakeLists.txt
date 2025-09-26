add_library(soupbinserver STATIC)
target_sources(soupbinserver PRIVATE src/server.cpp)
target_include_directories(soupbinserver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(soupbinserver PRIVATE soupbin_common)
