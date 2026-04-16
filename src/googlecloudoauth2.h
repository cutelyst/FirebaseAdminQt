#ifndef GOOGLECLOUDOAUTH2_H
#define GOOGLECLOUDOAUTH2_H

#include <firebaseadminexports.h>

#include <QElapsedTimer>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>

struct FIREBASE_ADMIN_QT_EXPORT GoogleCloudReply {
    QJsonObject data;
    bool error = false;
};

struct FIREBASE_ADMIN_QT_EXPORT GoogleCloudCode {
    std::optional<QPointer<const QObject>> receiver;
    std::function<void(const GoogleCloudReply &)> code;

    void call(const GoogleCloudReply &gcr) const {
        if (code && (!receiver.has_value() || receiver->isNull())) {
            code(gcr);
        }
    }
};

class FIREBASE_ADMIN_QT_EXPORT GoogleCloudOAuth2 : public QObject
{
    Q_OBJECT
public:
    explicit GoogleCloudOAuth2(QObject *parent = nullptr);

    void setAccountCredentialFile(const QString &filename);
    void setAccountCredentialData(const QByteArray &data);

    void setAccountCredential(const QJsonObject &accountCredential);
    QJsonObject accountCredential() const;

    QNetworkAccessManager *networkAccessManager() const;
    void setNetworkAccessManager(QNetworkAccessManager *nam);

    virtual QNetworkRequest defaultRequest(const QUrl &url) const;
    QByteArray accessTokenHeader() const;

    void setScopes(const QStringList &scopes);

    void getAccessToken();

    void getAccessToken(QObject *receiver,
                        std::function<void(const GoogleCloudReply &)> code);

protected:
    QNetworkAccessManager *m_nam;

private:
    QByteArray m_accessTokenHeader;
    QStringList m_scopes;
    QJsonObject m_credentialsFile;
    QJsonObject m_token;
    std::vector<GoogleCloudCode> m_codeToRun;
    QElapsedTimer m_expiresTimer;
    qint64 m_expires    = 0;
    bool m_gettingToken = false;
};

#endif // GOOGLECLOUDOAUTH2_H
