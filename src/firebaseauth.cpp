#include "firebaseauth.h"

#include "jwt-cpp/jwt.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>

#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(FIREBASE_AUTH, "firebase.auth")

class FirebaseAuthPrivate
{
public:
    QTimer *updateKeysTimer = nullptr;
    QNetworkAccessManager *m_nam = nullptr;
    QJsonObject m_firebaseConfig;
    // TODO we should cache the verifier instead
    QHash<QString, std::string> m_googlePubKeys;
};

FirebaseAuth::FirebaseAuth(QObject *parent)
    : QObject{parent}
    , d_ptr{new FirebaseAuthPrivate}
{
    d_ptr->m_nam = new QNetworkAccessManager{this};

    d_ptr->updateKeysTimer = new QTimer{this};
    d_ptr->updateKeysTimer->setInterval(60'000);
    d_ptr->updateKeysTimer->start();
    connect(d_ptr->updateKeysTimer, &QTimer::timeout, this, &FirebaseAuth::getGoogleSecureTokens);

    getGoogleSecureTokens();
}

FirebaseAuth::~FirebaseAuth()
{
    delete d_ptr;
}

QNetworkAccessManager *FirebaseAuth::networkAccessManager() const
{
    return d_ptr->m_nam;
}

void FirebaseAuth::setNetworkAccessManager(QNetworkAccessManager *nam)
{
    if (d_ptr->m_nam) {
        delete d_ptr->m_nam;
    }
    d_ptr->m_nam = nam;
}

void FirebaseAuth::setFirebaseConfig(const QJsonObject &config)
{
    d_ptr->m_firebaseConfig = config;
}

void FirebaseAuth::verifyIdToken(const std::string &token, QObject *context, std::function<void (const QJsonObject &, const QString &)> cb)
{
    if (cb) {
        QString error;
        QJsonObject decodedToken = verifyIdToken(token, error);
        if (context && error == u"pubkey-notfound") {
            connect(this, &FirebaseAuth::publicKeysUpdated, context, [this, token, cb] {
                QString error;
                QJsonObject decodedToken = verifyIdToken(token, error);
                cb(decodedToken, error);
            });
            getGoogleSecureTokens();
        } else {
            cb(decodedToken, error);
        }
    }
}

// https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
QJsonObject FirebaseAuth::verifyIdToken(const std::string &token, QString &error)
{
    QJsonObject ret;

    try {
        auto decoded = jwt::decode(token);

        // TODO add QJson traits to remove this
        for (auto &[key, value] : decoded.get_payload_json()) {
            if (value.is<std::string>()) {
                ret.insert(QString::fromStdString(key), QString::fromStdString(value.get<std::string>()));
            } else if (value.is<int64_t>()) {
                ret.insert(QString::fromStdString(key), static_cast<qint64>(value.get<int64_t>()));
            } else if (value.is<double>()) {
                ret.insert(QString::fromStdString(key), value.get<double>());
            } else {
                ret.insert(QString::fromStdString(key), QString::fromStdString(value.to_str()));
                qCWarning(FIREBASE_AUTH) << "SAVING CLAIM as JSON" << key.c_str() << value.to_str().c_str();
                break;
            }
        }

        const auto now = QDateTime::currentDateTime();
        if (now > QDateTime::fromSecsSinceEpoch(ret[u"exp"].toInteger())) {
            error = QStringLiteral("token-expired");
            return ret;
        }

        if (now < QDateTime::fromSecsSinceEpoch(ret[u"iat"].toInteger())) {
            error = QStringLiteral("token-issued-in-future");
            return ret;
        }

        const auto projectId = d_ptr->m_firebaseConfig[u"projectId"].toString();
        if (ret[u"aud"].toString() != projectId) {
            error = QStringLiteral("token-bad-audience");
            return ret;
        }

        if (ret[u"iss"].toString() != u"https://securetoken.google.com/" + projectId) {
            error = QStringLiteral("token-bad-issuer");
            return ret;
        }

        if (ret[u"sub"].toString().isEmpty()) {
            error = QStringLiteral("token-bad-subject");
            return ret;
        }

        if (now < QDateTime::fromSecsSinceEpoch(ret[u"auth_time"].toInteger())) {
            error = QStringLiteral("token-bad-auth-time");
            return ret;
        }

        const QString kid = QString::fromStdString(decoded.get_key_id());
        auto it = d_ptr->m_googlePubKeys.constFind(kid);
        if (it == d_ptr->m_googlePubKeys.constEnd()) {
            qCWarning(FIREBASE_AUTH) << "Pub Key Id not found" << kid;
            error = QStringLiteral("pubkey-notfound");
            return ret;
        }
        auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::rs256{ it.value() });
        verifier.verify(decoded);
    } catch (const jwt::error::rsa_exception &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED RSA:" << e.what();
    } catch (const jwt::error::token_verification_exception &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED VERIFICATION:" << e.what();
    } catch (const std::invalid_argument &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED DECODING:" << e.what();
    }
    return ret;
}


void FirebaseAuth::getGoogleSecureTokens()
{
    QNetworkRequest req(QUrl(QStringLiteral("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")));
    QNetworkReply *reply = d_ptr->m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [=, this] {
        reply->deleteLater();

        if (reply->error()) {
            qCWarning(FIREBASE_AUTH) << "Failed to get Google m_googlePubKeys";
        } else {
            const QByteArray data = reply->readAll();
            QJsonParseError error;
            QJsonDocument doc = QJsonDocument::fromJson(data, &error);
            if (error.error) {
                qCWarning(FIREBASE_AUTH) << "Google PubKeys ERROR" << error.errorString();
            } else {
                d_ptr->m_googlePubKeys.clear();

                const QJsonObject obj = doc.object();
                auto it = obj.constBegin();
                while (it != obj.constEnd()) {
                    const std::string cert = it.value().toString().toStdString();
                    if (!cert.empty()) {
                        d_ptr->m_googlePubKeys.insert(it.key(), cert);
                    }
                    ++it;
                }
                qCDebug(FIREBASE_AUTH) << "Got Google PubKeys" << d_ptr->m_googlePubKeys.keys();

                const QByteArray cacheControl = reply->rawHeader("Cache-control");
                auto pos = cacheControl.indexOf("max-age=");
                if (pos != -1) {
                    auto end = cacheControl.indexOf(',', pos);
                    bool ok;
                    int maxAge = cacheControl.mid(pos + 8, end - pos - 8).toInt(&ok);
                    if (ok) {
                        d_ptr->updateKeysTimer->setInterval(maxAge * 1'000);
                    }
                } else {
                    d_ptr->updateKeysTimer->setInterval(60'000);
                }

                return;
            }
        }

        QTimer::singleShot(1000, this, &FirebaseAuth::getGoogleSecureTokens);
    });
    connect(reply, &QNetworkReply::finished, this, &FirebaseAuth::publicKeysUpdated);
}
