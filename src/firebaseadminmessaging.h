#ifndef FIREBASEADMINMESSAGING_H
#define FIREBASEADMINMESSAGING_H

#include <firebaseadminexports.h>

#include <QJsonObject>
#include <QMap>
#include <QObject>
#include <QUrl>

class FIREBASE_ADMIN_QT_EXPORT FirebaseAndroidNotification
{
public:
    FirebaseAndroidNotification() = default;

    void setTitle(const QString &title);
    void setBody(const QString &body);
    void setIcon(const QString &icon);
    void setTag(const QString &tag);
    void setColor(const QString &color);
    void setData(const QMap<QString, QString> &data);

    bool isNull() const;
    QJsonObject object() const;

private:
    QJsonObject m_android;
    QJsonObject m_notification;
};

class FIREBASE_ADMIN_QT_EXPORT FirebaseApnsNotification
{
public:
    FirebaseApnsNotification() = default;

    void setHeaders(const QMap<QString, QString> &headers);
    void setPayload(const QJsonObject &payload);
    void setFcmOptions(const QString &analyticsLabel, const QString &image);

    bool isNull() const;
    QJsonObject object() const;

private:
    QJsonObject m_apnsFcmOptions;
    QJsonObject m_notification;
};

class FIREBASE_ADMIN_QT_EXPORT FirebaseMessage
{
public:
    FirebaseMessage();

    void setData(const QMap<QString, QString> &data);
    void setNotification(const QString &title, const QString &body);
    void setAndroid(const FirebaseAndroidNotification &android);
    void setApns(const FirebaseApnsNotification &apns);
    void setToken(const QString &token);
    void setTopic(const QString &topic);
    QString topic() const;
    void setCondition(const QString &condition);

    QJsonObject json() const;

private:
    QMap<QString, QString> m_data;
    std::pair<QString, QString> m_notification; // title & body
    FirebaseAndroidNotification m_android;
    FirebaseApnsNotification m_apns;
    // webpush
    QString m_token;
    QString m_topic;
    QString m_condition;
};

class FirebaseAdmin;
class FirebaseAdminReply;
class FIREBASE_ADMIN_QT_EXPORT FirebaseAdminMessaging : public QObject
{
    Q_OBJECT
public:
    explicit FirebaseAdminMessaging(FirebaseAdmin *parent);

    FirebaseAdminReply *send(const FirebaseMessage &message, bool validateOnly = false);

    FirebaseAdminReply *appInfo(const QString &iidToken, bool details = true);
    FirebaseAdminReply *appSubscribeToTopic(const QString &iidToken, const QString &topic);

    /*!
     * \brief appsSubscribeToTopic
     * \param iidTokens (max 1000 per call)
     * \param topic
     * \return
     */
    FirebaseAdminReply *appsSubscribeToTopic(const QStringList &iidTokens, const QString &topic);

    /*!
     * \brief appsUnsubscribeToTopic
     * \param iidTokens (max 1000 per call)
     * \param topic
     * \return
     */
    FirebaseAdminReply *appsUnsubscribeToTopic(const QStringList &iidTokens, const QString &topic);

private:
    QUrl fcmUrl() const;

    FirebaseAdmin *m_admin;
};

#endif // FIREBASEADMINMESSAGING_H
