#include "firebaseadminmessaging.h"

#include "firebaseadmin.h"
#include "firebaseadminreply.h"
#include "googlecloudoauth2.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>

using namespace Qt::StringLiterals;

FirebaseAdminMessaging::FirebaseAdminMessaging(FirebaseAdmin *parent)
    : QObject(parent)
    , m_admin(parent)
{
}

FirebaseAdminReply *FirebaseAdminMessaging::send(const FirebaseMessage &message, bool validateOnly)
{
    FirebaseAdminReply *reply = new FirebaseAdminReply;

    m_admin->getAccessToken(reply, [=, this](const GoogleCloudReply &credential) {
        if (credential.error) {
            Q_EMIT reply->finished(reply);
            return;
        }

        QJsonObject data = {
            {u"message"_s, message.json()},
        };
        if (validateOnly) {
            data[u"validate_only"] = true;
        }

        const QByteArray json     = QJsonDocument(data).toJson(QJsonDocument::Compact);
        const QNetworkRequest req = m_admin->defaultRequest(fcmUrl());

        QNetworkReply *namReply = m_admin->networkAccessManager()->post(req, json);
        reply->setNetworkReply(namReply);
    });

    return reply;
}

FirebaseAdminReply *FirebaseAdminMessaging::appInfo(const QString &iidToken, bool details)
{
    FirebaseAdminReply *reply = new FirebaseAdminReply;

    QUrl url(u"https://iid.googleapis.com/iid/info/" + iidToken);
    if (details) {
        url.setQuery(u"details=true"_s);
    }
    QNetworkRequest req = m_admin->defaultRequest(url);

    QNetworkReply *namReply = m_admin->networkAccessManager()->get(req);
    reply->setNetworkReply(namReply);
    return reply;
}

FirebaseAdminReply *FirebaseAdminMessaging::appSubscribeToTopic(const QString &iidToken,
                                                                const QString &topic)
{
    FirebaseAdminReply *reply = new FirebaseAdminReply;

    QUrl url(u"https://iid.googleapis.com/iid/v1/" + iidToken + u"/rel/topics/" + topic);

    QNetworkRequest req = m_admin->defaultRequest(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json"_ba);

    QNetworkReply *namReply = m_admin->networkAccessManager()->post(req, QByteArray());
    reply->setNetworkReply(namReply);
    return reply;
}

FirebaseAdminReply *FirebaseAdminMessaging::appsSubscribeToTopic(const QStringList &iidTokens,
                                                                 const QString &topic)
{
    FirebaseAdminReply *reply = new FirebaseAdminReply;

    QUrl url(u"https://iid.googleapis.com/iid/v1:batchAdd"_s);

    QJsonObject obj{
        {u"to"_s, QJsonValue(u"/topics/" + topic)},
        {u"registration_tokens"_s, QJsonArray::fromStringList(iidTokens)},
    };

    QNetworkRequest req = m_admin->defaultRequest(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json"_ba);

    QNetworkReply *namReply = m_admin->networkAccessManager()->post(
        req, QJsonDocument(obj).toJson(QJsonDocument::Compact));
    reply->setNetworkReply(namReply);
    return reply;
}

FirebaseAdminReply *FirebaseAdminMessaging::appsUnsubscribeToTopic(const QStringList &iidTokens,
                                                                   const QString &topic)
{
    FirebaseAdminReply *reply = new FirebaseAdminReply;

    QUrl url(u"https://iid.googleapis.com/iid/v1:batchRemove"_s);

    QJsonObject obj{
        {u"to"_s, QJsonValue(u"/topics/" + topic)},
        {u"registration_tokens"_s, QJsonArray::fromStringList(iidTokens)},
    };

    QNetworkRequest req = m_admin->defaultRequest(url);
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json"_ba);

    QNetworkReply *namReply = m_admin->networkAccessManager()->post(
        req, QJsonDocument(obj).toJson(QJsonDocument::Compact));
    reply->setNetworkReply(namReply);
    return reply;
}

QUrl FirebaseAdminMessaging::fcmUrl() const
{
    return QUrl{u"https://fcm.googleapis.com/v1/projects/" + m_admin->projectId() +
                u"/messages:send"};
}

FirebaseMessage::FirebaseMessage()
{
}

void FirebaseMessage::setData(const QMap<QString, QString> &data)
{
    m_data = data;
}

void FirebaseMessage::setNotification(const QString &title, const QString &body)
{
    m_notification = {title, body};
}

void FirebaseMessage::setAndroid(const FirebaseAndroidNotification &android)
{
    m_android = android;
}

void FirebaseMessage::setApns(const FirebaseApnsNotification &apns)
{
    m_apns = apns;
}

void FirebaseMessage::setToken(const QString &token)
{
    m_token = token;
}

void FirebaseMessage::setTopic(const QString &topic)
{
    m_topic = topic;
}

QString FirebaseMessage::topic() const
{
    return m_topic;
}

void FirebaseMessage::setCondition(const QString &condition)
{
    m_condition = condition;
}

QJsonObject FirebaseMessage::json() const
{
    QJsonObject ret;
    if (!m_token.isEmpty()) {
        ret[u"token"] = m_token;
    } else if (!m_topic.isEmpty()) {
        ret[u"topic"] = m_topic;
    } else if (!m_condition.isEmpty()) {
        ret[u"condition"] = m_condition;
    }

    if (!m_notification.first.isEmpty() && !m_notification.second.isEmpty()) {
        ret[u"notification"] = QJsonObject({
            {u"title"_s, m_notification.first},
            {u"body"_s, m_notification.second},
        });
    }

    if (!m_android.isNull()) {
        ret[u"android"] = m_android.object();
    }

    if (m_apns.isNull()) {
        ret[u"apns"] = m_apns.object();
    }

    if (!m_data.isEmpty()) {
        QJsonObject data;
        auto it = m_data.constBegin();
        while (it != m_data.constEnd()) {
            data[it.key()] = it.value();
            ++it;
        }
        ret[u"data"] = data;
    }

    return ret;
}

void FirebaseAndroidNotification::setTitle(const QString &title)
{
    m_notification[u"title"] = title;
}

void FirebaseAndroidNotification::setBody(const QString &body)
{
    m_notification[u"body"] = body;
}

void FirebaseAndroidNotification::setIcon(const QString &icon)
{
    m_notification[u"icon"] = icon;
}

void FirebaseAndroidNotification::setTag(const QString &tag)
{
    m_notification[u"tag"] = tag;
}

void FirebaseAndroidNotification::setColor(const QString &color)
{
    m_notification[u"color"] = color;
}

void FirebaseAndroidNotification::setData(const QMap<QString, QString> &data)
{
    QJsonObject obj;
    auto it = data.constBegin();
    while (it != data.constEnd()) {
        obj.insert(it.key(), it.value());
        ++it;
    }
    m_android[u"data"] = obj;
}

bool FirebaseAndroidNotification::isNull() const
{
    return m_android.isEmpty() && m_notification.isEmpty();
}

QJsonObject FirebaseAndroidNotification::object() const
{
    QJsonObject ret = m_android;
    ret.insert(u"ttl", u"600s"_s);

    ret.insert(u"notification", m_notification);

    return ret;
}

void FirebaseApnsNotification::setHeaders(const QMap<QString, QString> &headers)
{
    QJsonObject obj;
    auto it = headers.constBegin();
    while (it != headers.constEnd()) {
        obj.insert(it.key(), it.value());
        ++it;
    }
    m_notification[u"headers"] = obj;
}

void FirebaseApnsNotification::setPayload(const QJsonObject &payload)
{
    m_notification[u"payload"] = payload;
}

void FirebaseApnsNotification::setFcmOptions(const QString &analyticsLabel, const QString &image)
{
    m_apnsFcmOptions = {
        {u"analytics_label"_s, analyticsLabel},
        {u"image"_s, image},
    };
}

bool FirebaseApnsNotification::isNull() const
{
    return m_notification.isEmpty() && m_apnsFcmOptions.isEmpty();
}

QJsonObject FirebaseApnsNotification::object() const
{
    QJsonObject ret = m_notification;
    ret.insert(u"fcm_options", m_apnsFcmOptions);
    return ret;
}
