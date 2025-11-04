cmake_minimum_required(VERSION 3.16)
project(semantics-av VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_compile_definitions(_GLIBCXX_USE_CXX11_ABI=0)

include(GNUInstallDirs)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE PATH "Install prefix" FORCE)
endif()

if(CMAKE_INSTALL_PREFIX MATCHES "^(/usr|/opt)")
    set(IS_SYSTEM_INSTALL TRUE)
    message(STATUS "System installation mode: ${CMAKE_INSTALL_PREFIX}")
else()
    set(IS_SYSTEM_INSTALL FALSE)
    message(STATUS "User installation mode: ${CMAKE_INSTALL_PREFIX}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(cmake/Dependencies.cmake)
include(FetchSemanticsAV)

fetch_and_configure_semanticsav()

set(COMMON_SOURCES
    src/common/config.cpp
    src/common/logger.cpp
    src/common/types.cpp
    src/common/security.cpp
    src/common/paths.cpp
    src/common/progress_bar.cpp
)

set(CONFIG_SOURCES
    src/config/wizard.cpp
    src/config/validator.cpp
)

set(CORE_SOURCES
    src/core/engine.cpp
)

set(NETWORK_SOURCES
    src/network/client.cpp
    src/network/downloader.cpp
    src/network/analysis_service.cpp
)

set(HTTP_SOURCES
    src/http/error_codes.cpp
    src/http/response.cpp
)

set(DAEMON_SOURCES
    src/daemon/server.cpp
    src/daemon/handler.cpp
    src/daemon/protocol.cpp
    src/daemon/client.cpp
    src/daemon/client_pool.cpp
    src/daemon/http_server.cpp
)

set(SCAN_SOURCES
    src/scan/scanner.cpp
    src/scan/result_formatter.cpp
)

set(UPDATE_SOURCES
    src/update/updater.cpp
)

set(FORMAT_SOURCES
    src/format/format_utils.cpp
    src/format/json_formatter.cpp
    src/format/html_formatter.cpp
    src/format/markdown_formatter.cpp
    src/format/markdown_renderer.cpp
    src/format/console_formatter.cpp
)

set(REPORT_SOURCES
    src/report/storage.cpp
    src/report/converter.cpp
)

set(CLI_SOURCES
    src/cli/main_command.cpp
    src/cli/daemon_command.cpp
    src/cli/scan_command.cpp
    src/cli/update_command.cpp
    src/cli/analyze_command.cpp
    src/cli/config_command.cpp
    src/cli/report_command.cpp
)

set(ALL_SOURCES
    ${COMMON_SOURCES}
    ${CONFIG_SOURCES}
    ${CORE_SOURCES}
    ${NETWORK_SOURCES}
    ${HTTP_SOURCES}
    ${DAEMON_SOURCES}
    ${SCAN_SOURCES}
    ${UPDATE_SOURCES}
    ${FORMAT_SOURCES}
    ${REPORT_SOURCES}
    ${CLI_SOURCES}
)

add_executable(semantics-av
    src/main.cpp
    ${ALL_SOURCES}
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(COMMON_COMPILE_OPTIONS
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -fstack-protector-strong
        -fPIC
        -D_FORTIFY_SOURCE=2
    )
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        list(APPEND COMMON_COMPILE_OPTIONS -O3 -DNDEBUG)
    elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND COMMON_COMPILE_OPTIONS -O0 -g -fsanitize=address)
        set(COMMON_LINK_OPTIONS -fsanitize=address)
    endif()
    
    target_compile_options(semantics-av PRIVATE ${COMMON_COMPILE_OPTIONS})
    if(DEFINED COMMON_LINK_OPTIONS)
        target_link_options(semantics-av PRIVATE ${COMMON_LINK_OPTIONS})
    endif()
endif()

target_include_directories(semantics-av PRIVATE
    include
    ${cli11_SOURCE_DIR}/include
    ${spdlog_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
    ${json_SOURCE_DIR}/include
    ${inja_SOURCE_DIR}/include
    ${inja_SOURCE_DIR}/single_include
    ${md4c_SOURCE_DIR}/src
)

target_link_libraries(semantics-av PRIVATE
    SemanticsAV::Core
    spdlog::spdlog
    nlohmann_json::nlohmann_json
    toml11::toml11
    TBB::tbb
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    jemalloc::jemalloc
    md4c
)

set_target_properties(semantics-av PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    LINK_FLAGS "-static-libgcc -static-libstdc++"
    INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}:$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
    INSTALL_RPATH_USE_LINK_PATH TRUE
    BUILD_WITH_INSTALL_RPATH FALSE
)

install(TARGETS semantics-av DESTINATION ${CMAKE_INSTALL_BINDIR})

file(GLOB_RECURSE SEMANTICS_AV_SO_FILES 
    "${semantics_av_core_SOURCE_DIR}/lib/*.so"
    "${semantics_av_core_SOURCE_DIR}/lib/*.so.*")

if(SEMANTICS_AV_SO_FILES)
    install(FILES ${SEMANTICS_AV_SO_FILES} 
            DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif()

if(IS_SYSTEM_INSTALL)
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/semantics-av
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

    install(FILES systemd/semantics-av.service 
            DESTINATION /etc/systemd/system)

    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/semantics-av
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/semantics-av/models
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/log/semantics-av
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/run/semantics-av
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE)

    install(FILES config/semantics-av.conf.example
            DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/semantics-av
            RENAME semantics-av.conf.sample)

    install(PROGRAMS scripts/post_install.sh
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/semantics-av)

    install(CODE "
        message(STATUS \"\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"  SemanticsAV Installation Complete\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"\")
        message(STATUS \"Binary installed to:\")
        message(STATUS \"  ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/semantics-av\")
        message(STATUS \"\")
        message(STATUS \"Next steps:\")
        message(STATUS \"  1. Run system setup script:\")
        message(STATUS \"     sudo ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/semantics-av/post_install.sh\")
        message(STATUS \"\")
        message(STATUS \"  2. Configure the service:\")
        message(STATUS \"     sudo semantics-av config init\")
        message(STATUS \"\")
        message(STATUS \"  3. Start the service:\")
        message(STATUS \"     sudo systemctl start semantics-av\")
        message(STATUS \"\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"\")
    ")
else()
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/semantics-av
            DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
    
    install(FILES systemd/semantics-av-user.service
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/systemd/user
            RENAME semantics-av.service)
    
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/semantics-av)
    install(DIRECTORY DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/semantics-av/models)

    install(FILES config/semantics-av.conf.user
            DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/semantics-av
            RENAME semantics-av.conf.sample)

    install(PROGRAMS scripts/post_install_user.sh
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/semantics-av)
    
    install(CODE "
        message(STATUS \"\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"  SemanticsAV User Installation Complete\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"\")
        message(STATUS \"Binary installed to:\")
        message(STATUS \"  ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/semantics-av\")
        message(STATUS \"\")
        message(STATUS \"Next steps:\")
        message(STATUS \"  1. Run user setup script:\")
        message(STATUS \"     ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATAROOTDIR}/semantics-av/post_install_user.sh\")
        message(STATUS \"\")
        message(STATUS \"  2. Add to PATH:\")
        message(STATUS \"     export PATH=\\\"${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}:\\$PATH\\\"\")
        message(STATUS \"\")
        message(STATUS \"  3. Configure the service:\")
        message(STATUS \"     semantics-av config init\")
        message(STATUS \"\")
        message(STATUS \"  4. Enable user service:\")
        message(STATUS \"     systemctl --user enable semantics-av\")
        message(STATUS \"     systemctl --user start semantics-av\")
        message(STATUS \"\")
        message(STATUS \"═══════════════════════════════════════════════════════════\")
        message(STATUS \"\")
    ")
endif()

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
               ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
               @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
    COMMENT "Uninstalling SemanticsAV"
)