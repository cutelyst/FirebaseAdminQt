# SPDX-FileCopyrightText: (C) 2020-2024 Daniel Nicoletti <dantti12@gmail.com>
# SPDX-License-Identifier: MIT

#
# Custom C flags
#
macro(set_compiler_flags targetName)
  if(ENABLE_MAINTAINER_CFLAGS)
    target_compile_definitions(${targetName} PRIVATE QT_DEPRECATED_WARNINGS)

    if(NOT MSVC)
      target_compile_options(${targetName} PRIVATE
        -Wall
        -Wextra
        -Wcast-align
        -Wno-uninitialized
        -Wempty-body
        -Wformat-security
        -Wformat
        -Winit-self
        -Wunused-variable
      )
    endif()

    if(APPLE)
      target_compile_options(${targetName} PRIVATE -Wweak-vtables)
    endif()
  endif()

  # Enable -Werror
  if(NOT MSVC OR IS_CLANG_BUILD) # clang-cl accepts these too
    target_compile_options(${targetName} PRIVATE -Werror -Wundef -Wno-error=deprecated-declarations)
  endif()
endmacro()

add_definitions(
    -DQT_NO_KEYWORDS
    -DQT_NO_CAST_TO_ASCII
    -DQT_NO_CAST_FROM_ASCII
    -DQT_STRICT_ITERATORS
    -DQT_NO_URL_CAST_FROM_STRING
    -DQT_NO_CAST_FROM_BYTEARRAY
    -DQT_USE_QSTRINGBUILDER
    -DQT_NO_SIGNALS_SLOTS_KEYWORDS
    -DQT_USE_FAST_OPERATOR_PLUS
    -DQT_DISABLE_DEPRECATED_BEFORE=0x050c00
)

set(firebase_admin_SRC
    firebaseauth.cpp
    firebaseadmin.cpp
    firebaseadmincall.cpp
    firebaseadminmessaging.cpp
    firebaseadminreply.cpp
    googlecloudoauth2.cpp
)

set(firebase_admin_HEADERS
    firebaseauth.h
    firebaseadmin.h
    firebaseadmincall.h
    firebaseadminmessaging.h
    firebaseadminreply.h
    firebaseadminexports.h
    googlecloudoauth2.h
)

set(firebase_admin_HEADERS_PRIVATE
#     common.h
)

set(target FirebaseAdminQt${QT_VERSION_MAJOR})
add_library(${target}
    ${firebase_admin_SRC}
    ${firebase_admin_HEADERS}
    ${firebase_admin_HEADERS_PRIVATE}
    jwt/defaults.h
    jwt/traits.h
)
set_compiler_flags(${target})

#Add an alias so that library can be used inside the build tree, e.g. when testing
add_library(FirebaseAdminQt::Core ALIAS ${target})

if (CMAKE_GENERATOR MATCHES "Visual Studio")
  set_property(TARGET ${target} PROPERTY DEBUG_POSTFIX "d")
endif()

target_compile_definitions(${target}
    PRIVATE
        PLUGINS_PREFER_DEBUG_POSTFIX=$<CONFIG:Debug>
)

target_include_directories(${target} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:include/firebase-admin-qt${QT_VERSION_MAJOR}/FirebaseAdminQt>
)

set_target_properties(${target} PROPERTIES
    EXPORT_NAME Core
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

target_link_libraries(${target}
    PRIVATE
        Qt::Core
        Qt::Network
        jwt-cpp::jwt-cpp
)

set_property(TARGET ${target} PROPERTY PUBLIC_HEADER ${firebase_admin_HEADERS})
install(TARGETS ${target}
    EXPORT FirebaseAdminTargets DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION bin COMPONENT runtime
    ARCHIVE DESTINATION lib COMPONENT devel
    PUBLIC_HEADER DESTINATION include/firebase-admin-qt${QT_VERSION_MAJOR}/FirebaseAdminQt COMPONENT devel
)
