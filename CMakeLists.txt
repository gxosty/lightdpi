cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

set(PROJECT_NAME LightDPI)
set(LDPI_VERSION 1.0.0)
set(LDPI_CORE_LIB_NAME lightdpi)
set(LDPI_CLI_NAME lightdpi-cli)

option(LDPI_BUILD_CLI "Build command-line interface" ON)
option(LDPI_BUILD_SHARED_LIB "Build shared library (or static if switched off)" ON)

project(${PROJECT_NAME})

set(CMAKE_CXX_STANDARD 23)

add_compile_definitions(LDPI_VERSION="${LDPI_VERSION}")
add_compile_definitions(CURL_STATICLIB=1)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(LDPI_DEBUG=1)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)

list(APPEND LDPI_CORE_LIB_SOURCES
    # Core
    lightdpi/lightdpi.cxx
    lightdpi/utils.cxx

    # Common types
    lightdpi/common/buffer.cxx
    lightdpi/common/packet.cxx
    lightdpi/common/windivertwrapper.cxx

    # DNS
    lightdpi/dns/doh.cxx

    # Internal use sources
    lightdpi/internal/data.cxx
    lightdpi/internal/helpers.cxx

    # Modifiers
    lightdpi/modifiers/fakeack.cxx
    lightdpi/modifiers/fakettl.cxx
    lightdpi/modifiers/fakechecksum.cxx

    # Net helpers
    lightdpi/net/checksum.cxx
)

list(APPEND LDPI_CORE_LIB_LIBRARIES
    # Drivers
    WinDivert

    # Thirdparty
    libcurl.a
    libwolfssl.a
    libzlibstatic.a

    # System
    ws2_32
    advapi32
    wldap32
    crypt32
    bcrypt
)

if(LDPI_BUILD_SHARED_LIB)
    add_library(${LDPI_CORE_LIB_NAME} SHARED ${LDPI_CORE_LIB_SOURCES})
else()
    add_library(${LDPI_CORE_LIB_NAME} STATIC ${LDPI_CORE_LIB_SOURCES})
endif()

target_link_libraries(${LDPI_CORE_LIB_NAME}
    ${LDPI_CORE_LIB_LIBRARIES}
)

install(TARGETS ${LDPI_CORE_LIB_NAME} DESTINATION .)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/lib/WinDivert.dll DESTINATION .)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/lib/WinDivert64.sys DESTINATION .)

if(LDPI_BUILD_CLI)
    add_executable(${LDPI_CLI_NAME}
        lightdpi-cli/cli.cxx
        lightdpi-cli/config.cxx
    )

    target_link_libraries(${LDPI_CLI_NAME}
        ${LDPI_CORE_LIB_NAME}
    )

    install(TARGETS ${LDPI_CLI_NAME} DESTINATION .)
endif()