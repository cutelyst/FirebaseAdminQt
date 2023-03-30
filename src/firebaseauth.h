#ifndef FIREBASEAUTH_H
#define FIREBASEAUTH_H

#include <QObject>
#include <QJsonObject>
#include <QHash>

#include <string>
#include <functional>
#include <firebaseadminexports.h>

class QNetworkAccessManager;
class FIREBASE_ADMIN_QT_EXPORT FirebaseAuth : public QObject
{
    Q_OBJECT
public:
    explicit FirebaseAuth(QObject *parent = nullptr);

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

protected:
    static std::string getPubKeyFromCertificate(const std::string &certificate);

private:
    void getGoogleSecureTokens();
    QJsonObject verifyIdToken(const std::string &token, QString &error);

    QNetworkAccessManager *m_nam;
    QJsonObject m_firebaseConfig;
    QHash<QString, std::string> m_googlePubKeys;
};

#endif // FIREBASEAUTH_H
