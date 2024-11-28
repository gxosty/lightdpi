cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

set(PROJECT_NAME lightdpi)
set(PROJECT_VERSION "1.0.0")

set(LDPI_CORE_LIB_NAME lightdpi)
set(LDPI_CLI_NAME lightdpi-cli)

project(${PROJECT_NAME})

option(LDPI_BUILD_CLI "Build command-line interface" ON)
option(LDPI_BUILD_SHARED_LIB "Build shared library (or static if switched off)" ON)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)

add_compile_definitions(LDPI_VERSION ${PROJECT_VERSION})

list(APPEND LDPI_CORE_LIB_SOURCES
    lightdpi/lightdpi.cxx
    lightdpi/common/buffer.cxx
    lightdpi/common/packet.cxx
    lightdpi/common/windivertwrapper.cxx
)

if(LDPI_BUILD_SHARED_LIB)
    add_library(${LDPI_CORE_LIB_NAME} SHARED ${LDPI_CORE_LIB_SOURCES})
else()
    add_library(${LDPI_CORE_LIB_NAME} STAIC ${LDPI_CORE_LIB_SOURCES})
endif()

target_link_libraries(${LDPI_CORE_LIB_NAME}
    WinDivert
    curl
    wolfssl
    zlibstatic
)

if(LDPI_BUILD_CLI)
    add_executable(${LDPI_CLI_NAME}
        lightdpi-cli/cli.cxx
    )

    target_link_libraries(${LDPI_CLI_NAME}
        ${LDPI_CORE_LIB_NAME}
    )
endif()