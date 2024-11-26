#include "firebaseadmin.h"

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLoggingCategory>
#include <QProcess>

FirebaseAdmin::FirebaseAdmin(QObject *parent) : GoogleCloudOAuth2(parent) {
  setScopes({
      QStringLiteral("https://www.googleapis.com/auth/cloud-platform"),
      QStringLiteral("https://www.googleapis.com/auth/datastore"),
      QStringLiteral("https://www.googleapis.com/auth/devstorage.read_write"),
      QStringLiteral("https://www.googleapis.com/auth/firebase"),
      QStringLiteral("https://www.googleapis.com/auth/identitytoolkit"),
      QStringLiteral("https://www.googleapis.com/auth/userinfo.email"),
  });
}

QString FirebaseAdmin::projectId() const {
  return accountCredential()[QStringLiteral("project_id")].toString();
}

QByteArray FirebaseAdmin::clientVersionHeader() const {
  return QByteArrayLiteral("fire-admin-qt/0.1");
}

QNetworkRequest FirebaseAdmin::defaultRequest(const QUrl &url) const {
  QNetworkRequest req(url);
  req.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, true);
#if (QT_VERSION < QT_VERSION_CHECK(5, 15, 0))
  req.setAttribute(QNetworkRequest::HTTP2AllowedAttribute, true);
#else
  req.setAttribute(QNetworkRequest::Http2AllowedAttribute, true);
#endif
  req.setRawHeader(QByteArrayLiteral("AUTHORIZATION"), accessTokenHeader());

  req.setHeader(QNetworkRequest::ContentTypeHeader,
                QByteArrayLiteral("application/json"));
  req.setRawHeader(QByteArrayLiteral("X-GOOG-API-FORMAT-VERSION"),
                   QByteArrayLiteral("2"));
  req.setRawHeader(QByteArrayLiteral("X-FIREBASE-CLIENT"),
                   clientVersionHeader());

  return req;
}
