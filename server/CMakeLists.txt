add_library(soupbinserver STATIC)
target_sources(soupbinserver PRIVATE
    src/server.cpp
    src/detail/client_store.cpp
    src/detail/session.cpp
)
target_include_directories(soupbinserver
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_link_libraries(soupbinserver PRIVATE soupbin_common)

if(SOUPBIN_BUILD_TESTS)
    add_executable(soupbinserver_tests
        test/test_client_store.cpp
    )
    target_link_libraries(soupbinserver_tests PRIVATE
        soupbin_common
        soupbinserver
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(soupbinserver_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()
