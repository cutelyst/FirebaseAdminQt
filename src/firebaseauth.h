#ifndef FIREBASEAUTH_H
#define FIREBASEAUTH_H

#include <QObject>
#include <QJsonObject>

#include <string>
#include <functional>
#include <firebaseadminexports.h>

class QNetworkAccessManager;
class FirebaseAuthPrivate;
class FIREBASE_ADMIN_QT_EXPORT FirebaseAuth : public QObject
{
    Q_OBJECT
    Q_DECLARE_PRIVATE(FirebaseAuth)
public:
    explicit FirebaseAuth(QObject *parent = nullptr);
    ~FirebaseAuth();

    QNetworkAccessManager *networkAccessManager() const;
    void setNetworkAccessManager(QNetworkAccessManager *nam);

    /*!
     * \brief setFirebaseConfig in order to validate the token some
     * fields must match of this config.
     * \param config
     */
    void setFirebaseConfig(const QJsonObject &config);

    /*!
     * \brief verifyIdToken Verify that the token was created by google
     * \param token
     * \param error
     * \return
     */
    void verifyIdToken(const std::string &token, QObject *context, std::function<void(const QJsonObject &decodedToken, const QString &error)> cb);

Q_SIGNALS:
    void publicKeysUpdated();

private:
    void getGoogleSecureTokens();
    QJsonObject verifyIdToken(const std::string &token, QString &error);

    FirebaseAuthPrivate *d_ptr;
};

#endif // FIREBASEAUTH_H
