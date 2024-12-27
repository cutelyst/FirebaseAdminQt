#include "firebaseadmin.h"

#include <QJsonObject>
#include <QLoggingCategory>

using namespace Qt::StringLiterals;

FirebaseAdmin::FirebaseAdmin(QObject *parent)
    : GoogleCloudOAuth2(parent)
{
    setScopes({
        u"https://www.googleapis.com/auth/cloud-platform"_s,
        u"https://www.googleapis.com/auth/datastore"_s,
        u"https://www.googleapis.com/auth/devstorage.read_write"_s,
        u"https://www.googleapis.com/auth/firebase"_s,
        u"https://www.googleapis.com/auth/identitytoolkit"_s,
        u"https://www.googleapis.com/auth/userinfo.email"_s,
    });
}

QString FirebaseAdmin::projectId() const
{
    return accountCredential()[u"project_id"].toString();
}

QByteArray FirebaseAdmin::clientVersionHeader() const
{
    return "fire-admin-qt/0.1"_ba;
}

QNetworkRequest FirebaseAdmin::defaultRequest(const QUrl &url) const
{
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, true);
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
    req.setAttribute(QNetworkRequest::HTTP2AllowedAttribute, true);
#else
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, true);
#endif
    req.setRawHeader("AUTHORIZATION"_ba, accessTokenHeader());

    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json"_ba);
    req.setRawHeader("X-GOOG-API-FORMAT-VERSION"_ba, "2"_ba);
    req.setRawHeader("X-FIREBASE-CLIENT"_ba, clientVersionHeader());

    return req;
}
