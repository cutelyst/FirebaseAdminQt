# SPDX-FileCopyrightText: (C) 2020 Daniel Nicoletti <dantti12@gmail.com>
# SPDX-License-Identifier: MIT

set(firebase_admin_SRC
    firebaseadmin.cpp
    firebaseadmincall.cpp
    firebaseadminmessaging.cpp
    firebaseadminreply.cpp
    googlecloudoauth2.cpp
)

set(firebase_admin_HEADERS
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

add_library(FirebaseAdminQt${QT_VERSION_MAJOR}
    ${firebase_admin_SRC}
    ${firebase_admin_HEADERS}
    ${firebase_admin_HEADERS_PRIVATE}
)

#Add an alias so that library can be used inside the build tree, e.g. when testing
add_library(FirebaseAdminQt${QT_VERSION_MAJOR}::Core ALIAS FirebaseAdminQt${QT_VERSION_MAJOR})

if (CMAKE_GENERATOR MATCHES "Visual Studio")
  set_property(TARGET FirebaseAdminQt${QT_VERSION_MAJOR} PROPERTY DEBUG_POSTFIX "d")
endif()

target_compile_definitions(FirebaseAdminQt${QT_VERSION_MAJOR}
  PRIVATE
    PLUGINS_PREFER_DEBUG_POSTFIX=$<CONFIG:Debug>
)

target_include_directories(FirebaseAdminQt${QT_VERSION_MAJOR} PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/firebase-admin-qt${QT_VERSION_MAJOR}/FirebaseAdminQt>
)

set_target_properties(FirebaseAdminQt${QT_VERSION_MAJOR} PROPERTIES
    EXPORT_NAME Core
    VERSION ${PROJECT_VERSION}
    SOVERSION 0
)

target_link_libraries(FirebaseAdminQt${QT_VERSION_MAJOR}
    PRIVATE
        Qt${QT_VERSION_MAJOR}::Core
        Qt${QT_VERSION_MAJOR}::Network
)

set_property(TARGET FirebaseAdminQt${QT_VERSION_MAJOR} PROPERTY PUBLIC_HEADER ${firebase_admin_HEADERS})
install(TARGETS FirebaseAdminQt${QT_VERSION_MAJOR}
    EXPORT FirebaseAdminTargets DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION bin COMPONENT runtime
    ARCHIVE DESTINATION lib COMPONENT devel
    PUBLIC_HEADER DESTINATION include/firebase-admin-qt${QT_VERSION_MAJOR}/FirebaseAdminQt COMPONENT devel
)
