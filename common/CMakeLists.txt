add_library(soupbin_common INTERFACE)
target_include_directories(soupbin_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(SOUPBIN_ENABLE_LOGGING)
    include(FetchContent)
    FetchContent_Declare(
      spdlog
      GIT_REPOSITORY https://github.com/gabime/spdlog.git
      GIT_TAG v1.15.3
      GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(spdlog)

    target_link_libraries(soupbin_common INTERFACE spdlog::spdlog)
    target_compile_definitions(soupbin_common INTERFACE SOUPBIN_LOGGING_ENABLED)
endif()
