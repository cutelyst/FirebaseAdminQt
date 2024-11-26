#ifndef FIREBASEADMINREPLY_H
#define FIREBASEADMINREPLY_H

#include <QJsonObject>
#include <QNetworkReply>
#include <QObject>
#include <firebaseadminexports.h>

class FIREBASE_ADMIN_QT_EXPORT FirebaseAdminReply : public QObject {
  Q_OBJECT
public:
  explicit FirebaseAdminReply(QNetworkReply *reply = nullptr);

  void setNetworkReply(QNetworkReply *reply);

  /**
   * Requested entity not found, app uninstalled or dev got new id
   * Remove the token code from the db to avoid sending message to
   * invalid device.
   */
  bool error() const;

  QString messageId() const;
  int errorCode() const;
  QString errorMessage() const;
  QJsonObject data() const;

Q_SIGNALS:
  void finished(FirebaseAdminReply *reply);

private:
  QNetworkReply *m_reply = nullptr;
  QString m_messageId;
  QString m_errorMessage;
  QJsonObject m_data;
  int m_errorCode = 0;
  bool m_error = true;
};

#endif // FIREBASEADMINREPLY_H
