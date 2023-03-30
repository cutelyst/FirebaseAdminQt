#ifndef FIREBASEAUTH_H
#define FIREBASEAUTH_H

#include <QObject>
#include <QHash>

#include <string>
#include <functional>

class QNetworkAccessManager;
class FirebaseAuth : public QObject
{
    Q_OBJECT
public:
    explicit FirebaseAuth(QObject *parent = nullptr);

    QNetworkAccessManager *networkAccessManager() const;
    void setNetworkAccessManager(QNetworkAccessManager *nam);

    /*!
     * \brief verifyIdToken Verify that the token was created by google
     * \param token
     * \param error
     * \return
     */
    void verifyIdToken(const std::string &token, QObject *context, std::function<void(QJsonObject &token, QString &error)> cb);

Q_SIGNALS:
    void publicKeysUpdated();

protected:
    static std::string getPubKeyFromCertificate(const std::string &certificate);

private:
    void getGoogleSecureTokens();
    QJsonObject verifyIdToken(const std::string &token, QString &error);

    QNetworkAccessManager *m_nam;
    QHash<QString, std::string> m_googlePubKeys;
};

#endif // FIREBASEAUTH_H
