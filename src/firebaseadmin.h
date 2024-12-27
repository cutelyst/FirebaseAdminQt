#ifndef FIREBASEADMIN_H
#define FIREBASEADMIN_H

#include <firebaseadminexports.h>
#include <googlecloudoauth2.h>

#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QObject>
#include <QVariantHash>

class FIREBASE_ADMIN_QT_EXPORT FirebaseAdmin : public GoogleCloudOAuth2
{
    Q_OBJECT
public:
    explicit FirebaseAdmin(QObject *parent = nullptr);

    QString projectId() const;
    QByteArray clientVersionHeader() const;

    QNetworkRequest defaultRequest(const QUrl &url) const override;

Q_SIGNALS:
    void gotAccessToken(const QByteArray &token, bool success);
};

#endif // FIREBASEADMIN_H
