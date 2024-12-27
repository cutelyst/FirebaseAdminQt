#include "firebaseadminreply.h"

#include <QElapsedTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>

Q_LOGGING_CATEGORY(FIREBASE_ADMIN, "firebase.admin")

FirebaseAdminReply::FirebaseAdminReply(QNetworkReply *reply)
    : QObject(reply)
    , m_reply(reply)
{
}

void FirebaseAdminReply::setNetworkReply(QNetworkReply *reply)
{
    m_reply = reply;

    connect(reply, &QNetworkReply::finished, this, [=, this] {
        const QByteArray data = reply->readAll();
        const QJsonObject obj = QJsonDocument::fromJson(data).object();
        if (reply->error()) {
            qWarning(FIREBASE_ADMIN) << "FirebaseAdminReply error" << reply->error();
            const QJsonObject errorJ = obj[u"error"].toObject();
            m_error                  = true;
            m_errorCode              = errorJ[u"code"].toInt();
            m_errorMessage           = errorJ[u"message"].toString();
        } else {
            m_error     = false;
            m_messageId = obj[u"name"].toString();
            qDebug(FIREBASE_ADMIN) << "FirebaseAdminReply finished success" << m_messageId;
        }
        m_data = obj;
        Q_EMIT finished(this);
    });
}

bool FirebaseAdminReply::error() const
{
    return m_error;
}

QString FirebaseAdminReply::messageId() const
{
    return m_messageId;
}

int FirebaseAdminReply::errorCode() const
{
    return m_errorCode;
}

QString FirebaseAdminReply::errorMessage() const
{
    return m_errorMessage;
}

QJsonObject FirebaseAdminReply::data() const
{
    return m_data;
}
