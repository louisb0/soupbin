add_library(soupbinserver STATIC)
target_sources(soupbinserver PRIVATE
    src/server.cpp
    src/client_store.cpp
)
target_include_directories(soupbinserver PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(soupbinserver PRIVATE soupbin_common)

if(SOUPBIN_BUILD_TESTS)
    add_executable(soupbinserver_tests
        test/unit/test_client_store.cpp
    )
    target_link_libraries(soupbinserver_tests PRIVATE
        soupbinserver
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(soupbinserver_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()
