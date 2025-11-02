include(FetchContent)
include(CMakePackageConfigHelpers)

function(read_version_number version_var)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION_NUMBER")
        file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION_NUMBER" version_content)
        string(STRIP "${version_content}" version_content)
        set(${version_var} "${version_content}" PARENT_SCOPE)
    else()
        message(FATAL_ERROR "VERSION_NUMBER file not found")
    endif()
endfunction()

function(detect_platform platform_var filename_var)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
            set(platform "linux-x64")
            # x86_64: Built on CentOS 7 baseline (glibc 2.17, libstdc++ 3.4.19)
            # Compatible with: RHEL/CentOS 7+, Ubuntu 16.04+, Debian 9+
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
            set(platform "linux-arm64")
            # ARM64: Built on Ubuntu 18.04 baseline (glibc 2.27, libstdc++ 3.4.22)
            # Compatible with: RHEL/AlmaLinux 8+, Ubuntu 18.04+, Debian 10+
        else()
            message(FATAL_ERROR "Unsupported Linux architecture: ${CMAKE_SYSTEM_PROCESSOR}\n"
                                "SemanticsAV SDK supports:\n"
                                "  - x86_64 (glibc >= 2.17, libstdc++ >= 3.4.19)\n"
                                "  - aarch64/ARM64 (glibc >= 2.27, libstdc++ >= 3.4.22)")
        endif()
    else()
        message(FATAL_ERROR "Unsupported platform: ${CMAKE_SYSTEM_NAME}\n"
                            "SemanticsAV SDK is currently available for Linux only.\n"
                            "For other platforms, contact sales@metaforensics.ai")
    endif()
    
    set(${platform_var} "${platform}" PARENT_SCOPE)
    set(${filename_var} "semanticsav-public-${platform}-${SEMANTICS_AV_VERSION}.tgz" PARENT_SCOPE)
endfunction()

function(download_and_verify_hash url filename expected_hash_var)
    set(hash_url "${url}.sha256")
    set(hash_file "${CMAKE_CURRENT_BINARY_DIR}/${filename}.sha256")
    
    message(STATUS "Downloading hash file: ${hash_url}")
    file(DOWNLOAD "${hash_url}" "${hash_file}"
         STATUS download_status
         LOG download_log)
    
    list(GET download_status 0 status_code)
    if(NOT status_code EQUAL 0)
        message(FATAL_ERROR "Failed to download hash file: ${download_log}")
    endif()
    
    file(READ "${hash_file}" hash_content)
    string(STRIP "${hash_content}" hash_content)
    string(REGEX MATCH "^[a-fA-F0-9]+" expected_hash "${hash_content}")
    
    if(NOT expected_hash)
        message(FATAL_ERROR "Invalid hash format in ${hash_file}")
    endif()
    
    set(${expected_hash_var} "${expected_hash}" PARENT_SCOPE)
endfunction()

function(create_package_config_files semantics_av_root version)
    set(CONFIG_INSTALL_DIR "${CMAKE_CURRENT_BINARY_DIR}/semanticsav-config")
    
    set(SEMANTICS_AV_INCLUDE_DIR "${semantics_av_root}/include")
    set(SEMANTICS_AV_LIBRARY_DIR "${semantics_av_root}/lib")
    
    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SemanticsAVConfig.cmake.in"
        "${CONFIG_INSTALL_DIR}/SemanticsAVConfig.cmake"
        INSTALL_DESTINATION ${CONFIG_INSTALL_DIR}
        PATH_VARS SEMANTICS_AV_INCLUDE_DIR SEMANTICS_AV_LIBRARY_DIR
    )
    
    write_basic_package_version_file(
        "${CONFIG_INSTALL_DIR}/SemanticsAVConfigVersion.cmake"
        VERSION ${version}
        COMPATIBILITY SameMajorVersion
    )
    
    find_library(SEMANTICS_AV_LIBRARY
        NAMES semantics_av libsemantics_av
        PATHS ${SEMANTICS_AV_LIBRARY_DIR}
        NO_DEFAULT_PATH
    )
    
    file(WRITE "${CONFIG_INSTALL_DIR}/SemanticsAVTargets.cmake"
"if(NOT TARGET SemanticsAV::Core)
    add_library(SemanticsAV::Core SHARED IMPORTED)
    set_target_properties(SemanticsAV::Core PROPERTIES
        IMPORTED_LOCATION \"${SEMANTICS_AV_LIBRARY}\"
        INTERFACE_INCLUDE_DIRECTORIES \"${SEMANTICS_AV_INCLUDE_DIR}\"
        IMPORTED_NO_SONAME TRUE
    )
endif()
")
    
    set(CMAKE_PREFIX_PATH "${CONFIG_INSTALL_DIR};${CMAKE_PREFIX_PATH}" CACHE STRING "" FORCE)
    
    message(STATUS "Package config files created at: ${CONFIG_INSTALL_DIR}")
endfunction()

function(fetch_and_configure_semanticsav)
    read_version_number(SEMANTICS_AV_VERSION)
    detect_platform(SEMANTICS_AV_PLATFORM SEMANTICS_AV_FILENAME)
    
    set(SEMANTICS_AV_BASE_URL "https://libs.semanticsav.ai/v${SEMANTICS_AV_VERSION}")
    set(SEMANTICS_AV_URL "${SEMANTICS_AV_BASE_URL}/${SEMANTICS_AV_FILENAME}")
    
    download_and_verify_hash("${SEMANTICS_AV_URL}" "${SEMANTICS_AV_FILENAME}" SEMANTICS_AV_HASH)
    
    message(STATUS "Fetching SemanticsAV v${SEMANTICS_AV_VERSION} for ${SEMANTICS_AV_PLATFORM}")
    
    FetchContent_Declare(
        semantics_av_core
        URL ${SEMANTICS_AV_URL}
        URL_HASH SHA256=${SEMANTICS_AV_HASH}
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    
    FetchContent_GetProperties(semantics_av_core)
    if(NOT semantics_av_core_POPULATED)
        FetchContent_Populate(semantics_av_core)
        
        set(SEMANTICS_AV_ROOT ${semantics_av_core_SOURCE_DIR})
        set(SEMANTICS_AV_INCLUDE_DIR ${SEMANTICS_AV_ROOT}/include)
        set(SEMANTICS_AV_LIBRARY_DIR ${SEMANTICS_AV_ROOT}/lib)
        
        if(NOT EXISTS ${SEMANTICS_AV_INCLUDE_DIR}/semantics_av/semantics_av.hpp)
            message(FATAL_ERROR "SemanticsAV headers not found in downloaded package")
        endif()
        
        find_library(SEMANTICS_AV_LIBRARY
            NAMES semantics_av libsemantics_av
            PATHS ${SEMANTICS_AV_LIBRARY_DIR}
            NO_DEFAULT_PATH
        )
        
        if(NOT SEMANTICS_AV_LIBRARY)
            message(FATAL_ERROR "SemanticsAV library not found in downloaded package")
        endif()
        
        add_library(SemanticsAV::Core SHARED IMPORTED GLOBAL)
        set_target_properties(SemanticsAV::Core PROPERTIES
            IMPORTED_LOCATION ${SEMANTICS_AV_LIBRARY}
            INTERFACE_INCLUDE_DIRECTORIES ${SEMANTICS_AV_INCLUDE_DIR}
            IMPORTED_NO_SONAME TRUE
        )
        
        file(GLOB SEMANTICS_AV_LIBS "${SEMANTICS_AV_LIBRARY_DIR}/*")
        install(FILES ${SEMANTICS_AV_LIBS} DESTINATION lib)
        
        create_package_config_files(${SEMANTICS_AV_ROOT} ${SEMANTICS_AV_VERSION})
        
        message(STATUS "SemanticsAV Core Library v${SEMANTICS_AV_VERSION} configured successfully")
    endif()
endfunction()