/* 
 * SPDX-FileCopyrightText: (C) 2021 Daniel Nicoletti <dantti12@gmail.com>
 * SPDX-License-Identifier: MIT
 */

#ifndef FIREBASE_ADMIN_QT_EXPORT_H
#define FIREBASE_ADMIN_QT_EXPORT_H

#include <QtCore/QtGlobal>

#if defined(FirebaseAdminQt5_EXPORTS)
#define FIREBASE_ADMIN_QT_EXPORT Q_DECL_EXPORT
#else
#define FIREBASE_ADMIN_QT_EXPORT Q_DECL_IMPORT
#endif

#endif
