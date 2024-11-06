#include "googlecloudoauth2.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>
#include <QFile>

#include <QLoggingCategory>

#include "jwt-cpp/jwt.h"

Q_LOGGING_CATEGORY(GC_OAUTH, "gc.oauth", QtInfoMsg)

using namespace Qt::StringLiterals;

GoogleCloudOAuth2::GoogleCloudOAuth2(QObject *parent) : QObject(parent)
  , m_nam(new QNetworkAccessManager(this))
{
}

void GoogleCloudOAuth2::setAccountCredentialFile(const QString &filename)
{
    QFile file(filename);
    if (file.open(QFile::ReadOnly)) {
        setAccountCredentialData(file.readAll());
    } else {
        qCWarning(GC_OAUTH) << "Failed to open credentials file" << filename << file.errorString();
    }
}

void GoogleCloudOAuth2::setAccountCredentialData(const QByteArray &data)
{
    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);
    if (!error.error) {
        setAccountCredential(doc.object());
    } else {
        qCWarning(GC_OAUTH) << "Failed to parse credentials data" << error.errorString();
    }
}

void GoogleCloudOAuth2::setAccountCredential(const QJsonObject &accountCredential)
{
    m_credentialsFile = accountCredential;
}

QJsonObject GoogleCloudOAuth2::accountCredential() const
{
    return m_credentialsFile;
}

QNetworkAccessManager *GoogleCloudOAuth2::networkAccessManager() const
{
    return m_nam;
}

void GoogleCloudOAuth2::setNetworkAccessManager(QNetworkAccessManager *nam)
{
    if (m_nam) {
        delete m_nam;
    }
    m_nam = nam;
}

QNetworkRequest GoogleCloudOAuth2::defaultRequest(const QUrl &url) const
{
    QNetworkRequest req(url);
    req.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, true);
//    req.setAttribute(QNetworkRequest::HTTP2AllowedAttribute, true); // Not yet Google?
    req.setRawHeader(QByteArrayLiteral("AUTHORIZATION"), m_accessTokenHeader);

    return req;
}

QByteArray GoogleCloudOAuth2::accessTokenHeader() const
{
    return m_accessTokenHeader;
}

void GoogleCloudOAuth2::setScopes(const QStringList &scopes)
{
    m_scopes = scopes;
}

void GoogleCloudOAuth2::getAccessToken()
{
    const QString tokenUri = m_credentialsFile[u"token_uri"].toString();
    const QString privateKey = m_credentialsFile[u"private_key"].toString();

    try {
        auto algo = jwt::algorithm::rs256{std::string(), privateKey.toStdString()};

        auto token = jwt::create()
                .set_type("JWT")
                .set_issuer(m_credentialsFile[u"client_email"].toString().toStdString())
                .set_payload_claim("scope", jwt::claim(m_scopes.join(u' ').toStdString()))
                .set_audience(tokenUri.toStdString())
                .set_issued_at(std::chrono::system_clock::now())
                .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{3600})
                .sign(algo);

        QUrlQuery query;
        query.addQueryItem(u"grant_type"_s, u"urn:ietf:params:oauth:grant-type:jwt-bearer"_s);
        query.addQueryItem(u"assertion"_s, QString::fromStdString(token));

        QNetworkRequest req(QUrl{tokenUri});
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded"_ba);

        QNetworkReply *reply = m_nam->post(req, query.toString(QUrl::FullyEncoded).toLatin1());
        connect(reply, &QNetworkReply::finished, this, [=, this] {
            reply->deleteLater();
            const QByteArray data = reply->readAll();
            m_token = QJsonObject();
            m_accessTokenHeader.clear();
            GoogleCloudReply gcr;

            if (!reply->error()) {
                QJsonParseError error;
                QJsonDocument doc = QJsonDocument::fromJson(data, &error);
                if (!error.error) {
                    m_token = doc.object();
                    m_accessTokenHeader = QByteArrayLiteral("Bearer ") + m_token.value(QStringLiteral("access_token")).toString().toLatin1();
                    m_expires = m_token.value(QLatin1String("expires_in")).toInt() * 1000 - 30'000;
                    m_expiresTimer.start();
                    qCDebug(GC_OAUTH) << "Got Access Token" << m_token;
                } else {
                    gcr.error = true;
                    qCWarning(GC_OAUTH) << "Failed to parse google token file" << data << error.errorString();
                }
            } else {
                gcr.error = true;
                qCWarning(GC_OAUTH) << "Get Access Token failed" << reply->error();
            }

            for (const auto &code : m_codeToRun) {
                if (code.receiver) {
                    code.code(gcr);
                }
            }
            m_codeToRun.clear();

            m_gettingToken = false;
        });
        m_gettingToken = true;
    } catch (const jwt::error::rsa_exception &e) {
        qCDebug(GC_OAUTH) << "FAILED RSA:" << e.what();
        GoogleCloudReply gcr;
        gcr.error = true;
        for (const auto &code : m_codeToRun) {
            if (code.receiver) {
                code.code(gcr);
            }
        }
        m_codeToRun.clear();
    }
}

void GoogleCloudOAuth2::getAccessToken(const QObject *receiver, std::function<void (const GoogleCloudReply &)> code)
{
    if (!m_token.isEmpty() && !m_expiresTimer.hasExpired(m_expires)) {
        code(GoogleCloudReply());
    } else {
        m_codeToRun.push_back(GoogleCloudCode{ receiver, code });
        if (!m_gettingToken) {
            getAccessToken();
        }
    }
}
