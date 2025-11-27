include(FetchContent)
include(ExternalProject)

set(CLI11_VERSION "v2.5.0")
set(SPDLOG_VERSION "v1.15.3")
set(HTTPLIB_VERSION "v0.28.0")
set(JSON_VERSION "v3.12.0")
set(TOML11_VERSION "v4.4.0")
set(TBB_VERSION "v2022.3.0")
set(JEMALLOC_VERSION "5.3.0")
set(INJA_VERSION "v3.4.0")
set(MD4C_VERSION "release-0.5.2")
set(LIBARCHIVE_VERSION "v3.8.3")

FetchContent_Declare(cli11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG ${CLI11_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG ${SPDLOG_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG ${HTTPLIB_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG ${JSON_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(toml11
    GIT_REPOSITORY https://github.com/ToruNiina/toml11.git
    GIT_TAG ${TOML11_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(tbb
    GIT_REPOSITORY https://github.com/oneapi-src/oneTBB.git
    GIT_TAG ${TBB_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(inja
    GIT_REPOSITORY https://github.com/pantor/inja.git
    GIT_TAG ${INJA_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(md4c
    GIT_REPOSITORY https://github.com/mity/md4c.git
    GIT_TAG ${MD4C_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(libarchive
    GIT_REPOSITORY https://github.com/libarchive/libarchive.git
    GIT_TAG ${LIBARCHIVE_VERSION}
    GIT_SHALLOW TRUE
)

set(TBB_TEST OFF CACHE BOOL "" FORCE)
set(TBB_EXAMPLES OFF CACHE BOOL "" FORCE)
set(TBB_STRICT OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(cli11 spdlog httplib toml11 tbb)

FetchContent_MakeAvailable(json)

set(INJA_USE_EMBEDDED_JSON OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(inja)

FetchContent_GetProperties(md4c)
if(NOT md4c_POPULATED)
    FetchContent_Populate(md4c)
    
    add_library(md4c STATIC
        ${md4c_SOURCE_DIR}/src/md4c.c
        ${md4c_SOURCE_DIR}/src/md4c-html.c
        ${md4c_SOURCE_DIR}/src/entity.c
    )
    
    target_include_directories(md4c PUBLIC
        ${md4c_SOURCE_DIR}/src
    )
    
    set_target_properties(md4c PROPERTIES
        C_STANDARD 99
        POSITION_INDEPENDENT_CODE ON
    )
endif()

set(ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(ENABLE_TAR OFF CACHE BOOL "" FORCE)
set(ENABLE_CPIO OFF CACHE BOOL "" FORCE)
set(ENABLE_CAT OFF CACHE BOOL "" FORCE)
set(ENABLE_XATTR OFF CACHE BOOL "" FORCE)
set(ENABLE_ACL OFF CACHE BOOL "" FORCE)
set(ENABLE_ICONV OFF CACHE BOOL "" FORCE)
set(ENABLE_LIBB2 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZ4 OFF CACHE BOOL "" FORCE)
set(ENABLE_LZO OFF CACHE BOOL "" FORCE)
set(ENABLE_LZMA OFF CACHE BOOL "" FORCE)
set(ENABLE_ZSTD OFF CACHE BOOL "" FORCE)
set(ENABLE_NETTLE OFF CACHE BOOL "" FORCE)
set(ENABLE_OPENSSL OFF CACHE BOOL "" FORCE)
set(ENABLE_MBEDTLS OFF CACHE BOOL "" FORCE)
set(ENABLE_CNG OFF CACHE BOOL "" FORCE)
set(ENABLE_LIBXML2 OFF CACHE BOOL "" FORCE)
set(ENABLE_EXPAT OFF CACHE BOOL "" FORCE)
set(ENABLE_PCRE2POSIX OFF CACHE BOOL "" FORCE)
set(ENABLE_LibGCC OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(libarchive)

set(JEMALLOC_PREFIX ${CMAKE_BINARY_DIR}/_deps/jemalloc-build)
set(JEMALLOC_INSTALL_DIR ${JEMALLOC_PREFIX}/install)

file(MAKE_DIRECTORY ${JEMALLOC_INSTALL_DIR}/include)
file(MAKE_DIRECTORY ${JEMALLOC_INSTALL_DIR}/lib)

ExternalProject_Add(
    jemalloc_build
    URL https://github.com/jemalloc/jemalloc/releases/download/${JEMALLOC_VERSION}/jemalloc-${JEMALLOC_VERSION}.tar.bz2
    URL_HASH SHA256=2db82d1e7119df3e71b7640219b6dfe84789bc0537983c3b7ac4f7189aecfeaa
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    PREFIX ${JEMALLOC_PREFIX}
    CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=${JEMALLOC_INSTALL_DIR} --disable-shared --enable-static
    BUILD_COMMAND make -j4
    INSTALL_COMMAND make install
    BUILD_IN_SOURCE 0
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
)

add_library(jemalloc::jemalloc STATIC IMPORTED GLOBAL)
set_target_properties(jemalloc::jemalloc PROPERTIES
    IMPORTED_LOCATION ${JEMALLOC_INSTALL_DIR}/lib/libjemalloc.a
    INTERFACE_INCLUDE_DIRECTORIES ${JEMALLOC_INSTALL_DIR}/include
)
add_dependencies(jemalloc::jemalloc jemalloc_build)

message(STATUS "Jemalloc ${JEMALLOC_VERSION} configured")
message(STATUS "Inja ${INJA_VERSION} configured")
message(STATUS "MD4C ${MD4C_VERSION} configured")
message(STATUS "LibArchive ${LIBARCHIVE_VERSION} configured")

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)