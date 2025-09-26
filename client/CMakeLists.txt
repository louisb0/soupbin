add_library(soupbinclient STATIC)
target_sources(soupbinclient PRIVATE src/client.cpp)
target_include_directories(soupbinclient PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(soupbinclient PRIVATE soupbin_common)
