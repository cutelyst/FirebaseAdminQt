#ifndef FIREBASEADMINCALL_H
#define FIREBASEADMINCALL_H

#include <firebaseadminexports.h>

#include <QObject>

class FIREBASE_ADMIN_QT_EXPORT FirebaseAdminCall : public QObject
{
    Q_OBJECT
public:
    explicit FirebaseAdminCall(QObject *parent = nullptr);
};

#endif // FIREBASEADMINCALL_H
