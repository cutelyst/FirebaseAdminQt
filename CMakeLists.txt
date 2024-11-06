# SPDX-FileCopyrightText: (C) 2021-2024 Daniel Nicoletti <dantti12@gmail.com>
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.16)
project(FirebaseAdmin VERSION 0.2.0 LANGUAGES CXX)

if(NOT DEFINED QT_VERSION_MAJOR)
    find_package(QT NAMES Qt6 COMPONENTS Core Network REQUIRED)
endif()
find_package(Qt${QT_VERSION_MAJOR} 6.4.0 COMPONENTS Core Network REQUIRED)

include(GNUInstallDirs)
include(FetchContent)

FetchContent_Declare(
    JwtCpp
    GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
    GIT_TAG        6dd190d
    EXCLUDE_FROM_ALL
)
set(JWT_BUILD_EXAMPLES off)
FetchContent_MakeAvailable(JwtCpp)

set(CMAKE_AUTOMOC ON)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

# Include our cmake modules
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules)

# As moc files are generated in the binary dir, tell CMake
# to always look for includes there:
set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Forbid in-tree building
if(CMAKE_CURRENT_SOURCE_DIR MATCHES CMAKE_BINARY_DIR)
    message(STATUS "Please do an out-of-tree build:")
    message(STATUS "rm -f CMakeCache.txt && mkdir build && cd build; cmake .. && make")
    message(FATAL_ERROR "In-tree-build detected!")
endif()

#
# Options
#
option(ENABLE_MAINTAINER_CFLAGS "Enable maintainer CFlags" OFF)

# NONE

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX
        "/usr" CACHE PATH "firebase admin default install prefix" FORCE)
endif()

add_definitions("-DLOCALSTATEDIR=\"${LOCALSTATEDIR}\"")

set(CMAKE_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/lib/${CMAKE_LIBRARY_ARCHITECTURE}" CACHE PATH "Output directory for libraries")

option(BUILD_SHARED_LIBS "Build in shared lib mode" ON)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/FirebaseAdmin
)

# cmake config files
configure_file(${CMAKE_MODULE_PATH}/firebase-admin-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/FirebaseAdminQt${QT_VERSION_MAJOR}Config.cmake
    @ONLY
)
configure_file(${CMAKE_MODULE_PATH}/firebase-admin-config-version.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/FirebaseAdminQt${QT_VERSION_MAJOR}ConfigVersion.cmake
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/FirebaseAdminQt${QT_VERSION_MAJOR}Config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/FirebaseAdminQt${QT_VERSION_MAJOR}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FirebaseAdminQt${QT_VERSION_MAJOR}/
)

install(EXPORT FirebaseAdminTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/FirebaseAdminQt${QT_VERSION_MAJOR}/
    FILE FirebaseAdmin${PROJECT_VERSION_MAJOR}Qt${QT_VERSION_MAJOR}Targets.cmake
    NAMESPACE FirebaseAdminQt::
    COMPONENT Devel
)

add_subdirectory(src)
include(CPackConfig)
