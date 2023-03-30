#include "firebaseauth.h"

#include "jwt-cpp/jwt.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>

#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

#include <QLoggingCategory>

Q_LOGGING_CATEGORY(FIREBASE_AUTH, "firebase.auth")

FirebaseAuth::FirebaseAuth(QObject *parent)
    : QObject{parent}
    , m_nam{new QNetworkAccessManager(this)}
{
    getGoogleSecureTokens();

    auto updateKeys = new QTimer{this};
    updateKeys->setInterval(5 * 60'000);
    updateKeys->start();
    connect(updateKeys, &QTimer::timeout, this, &FirebaseAuth::getGoogleSecureTokens);
}

QNetworkAccessManager *FirebaseAuth::networkAccessManager() const
{
    return m_nam;
}

void FirebaseAuth::setNetworkAccessManager(QNetworkAccessManager *nam)
{
    if (m_nam) {
        delete m_nam;
    }
    m_nam = nam;
}

void FirebaseAuth::setFirebaseConfig(const QJsonObject &config)
{
    m_firebaseConfig = config;
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
        for (auto &e : decoded.get_payload_claims()) {
            switch (e.second.get_type()) {
            case jwt::json::type::string:
                ret.insert(QString::fromStdString(e.first), QString::fromStdString(e.second.as_string()));
                break;
            case jwt::json::type::integer:
                ret.insert(QString::fromStdString(e.first), static_cast<qint64>(e.second.as_int()));
                break;
            case jwt::json::type::number:
                ret.insert(QString::fromStdString(e.first), static_cast<double>(e.second.as_number()));
                break;
            default:
                ret.insert(QString::fromStdString(e.first), QString::fromStdString(e.second.to_json().to_str()));
                qCWarning(FIREBASE_AUTH) << "SAVING CLAIM as JSON" << e.first.c_str() << e.second.to_json().to_str().c_str();
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

        const auto projectId = m_firebaseConfig[u"projectId"].toString();
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
        auto it = m_googlePubKeys.constFind(kid);
        if (it == m_googlePubKeys.constEnd()) {
            qCWarning(FIREBASE_AUTH) << "Pub Key Id not found" << kid;
            error = QStringLiteral("pubkey-notfound");
            return ret;
        }
        const std::string pubkey = it.value();

        auto verifier = jwt::verify()
                .allow_algorithm(jwt::algorithm::rs256{ pubkey });

        verifier.verify(decoded);
    } catch (const jwt::rsa_exception &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED RSA:" << e.what();
    } catch (const jwt::token_verification_exception &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED VERIFICATION:" << e.what();
    } catch (const std::invalid_argument &e) {
        error = QString::fromLatin1(e.what());
        qCDebug(FIREBASE_AUTH) << "FAILED DECODING:" << e.what();
    }
    return ret;
}

std::string FirebaseAuth::getPubKeyFromCertificate(const std::string &certificate)
{
    std::string retPubKey;
    EVP_PKEY *pkey = nullptr;
    X509     *cert = nullptr;

    /* ---------------------------------------------------------- *
     * These function calls initialize openssl for correct work.  *
     * ---------------------------------------------------------- */
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    /* ---------------------------------------------------------- *
     * Create the Input/Output BIO's.                             *
     * ---------------------------------------------------------- */
    std::unique_ptr<BIO, decltype(&BIO_free_all)> cert_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if ((size_t)BIO_write(cert_bio.get(), certificate.data(), certificate.size()) != certificate.size()) {
        qDebug(FIREBASE_AUTH) << "failed to load public key: bio_write failed";
        return retPubKey;
    }

    std::unique_ptr<BIO, decltype(&BIO_free_all)> out_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    /* ---------------------------------------------------------- *
      * Load the certificate (PEM).                      *
      * ---------------------------------------------------------- */
    if (! (cert = PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr))) {
        qDebug(FIREBASE_AUTH) << "Error loading cert into memory";
        return retPubKey;
    }

    /* ---------------------------------------------------------- *
      * Extract the certificate's public key data.                 *
      * ---------------------------------------------------------- */
    if ((pkey = X509_get_pubkey(cert)) == nullptr) {
        qDebug(FIREBASE_AUTH) << "Error getting public key from certificate";
        return  retPubKey;
    }


    if(!PEM_write_bio_PUBKEY(out_bio.get(), pkey)) {
        qDebug(FIREBASE_AUTH) << "Error writing public key data in PEM format";
        return retPubKey;
    }

    const char *p;
    size_t len = size_t(BIO_get_mem_data(out_bio.get(), &p));
    retPubKey.append(p, len);

    EVP_PKEY_free(pkey);
    X509_free(cert);

    return retPubKey;
}

void FirebaseAuth::getGoogleSecureTokens()
{
    QNetworkRequest req(QUrl(QStringLiteral("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")));
    QNetworkReply *reply = m_nam->get(req);
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
                m_googlePubKeys.clear();

                const QJsonObject obj = doc.object();
                auto it = obj.constBegin();
                while (it != obj.constEnd()) {
                    const std::string cert = it.value().toString().toStdString();
                    const std::string pubKey = FirebaseAuth::getPubKeyFromCertificate(cert);
                    if (!pubKey.empty()) {
                        m_googlePubKeys.insert(it.key(), pubKey);
                    }
                    ++it;
                }
                qCDebug(FIREBASE_AUTH) << "Got Google PubKeys" << m_googlePubKeys.keys();

                return;
            }
        }

        QTimer::singleShot(1000, this, &FirebaseAuth::getGoogleSecureTokens);
    });
    connect(reply, &QNetworkReply::finished, this, &FirebaseAuth::publicKeysUpdated);
}
