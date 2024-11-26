#ifndef JWT_CPP_QT_JSON_TRAITS_H
#define JWT_CPP_QT_JSON_TRAITS_H

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <stdexcept>
#include <type_traits>

#define JWT_DISABLE_PICOJSON
#include <jwt-cpp/jwt.h>

namespace jwt {
/**
 * \brief Namespace containing all the json_trait implementations for a
 * jwt::basic_claim.
 */
namespace traits {

struct qt_json {
  // Type Specifications
  using string_type =
      std::string; // current limitation of traits implementation
  using number_type = double;
  using integer_type = qint64;
  using boolean_type = bool;

  struct value_type : QJsonValue {
    using QJsonValue::QJsonValue; // Inherit constructors from QJsonValue

    value_type(const std::string &value)
        : QJsonValue{QString::fromStdString(value)} {}
  };

  struct object_type : QJsonObject {
    using QJsonObject::QJsonObject; // Inherit constructors from QJsonObject

    // Add missing C++11 member types
    // using value_type = key_value_type; // Enable optional jwt-cpp methods
    // using mapped_type = key_value_type::value_type;
    using size_type = size_t; // for implementing count

    // object_type() = default;
    // object_type(const object_type&) = default;
    explicit object_type(const QJsonObject &o) : QJsonObject(o) {}
    // object_type(object_type&&) = default;
    explicit object_type(QJsonObject &&o) : QJsonObject(o) {}
    // ~object_type() = default;
    // object_type& operator=(const object_type& o) = default;
    // object_type& operator=(object_type&& o) noexcept = default;

    // Add missing C++11 subscription operator
    QJsonValue operator[](const std::string &key) {
      QJsonValueRef ref = QJsonObject::operator[](QString::fromStdString(key));
      return ref;
    }

    // Add missing C++11 element access
    QJsonValue at(const std::string &key) const {
      auto it = constFind(QString::fromStdString(key));
      if (it != constEnd()) {
        return it.value();
      }

      throw std::out_of_range("invalid key");
    }

    // Add missing C++11 lookup method
    size_type count(const std::string &key) const {
      return contains(QString::fromStdString(key)) ? 0 : 1;
    }
  };

  struct array_type : QJsonArray {
    using QJsonArray::QJsonArray; // Inherit constructors from QJsonArray

    explicit array_type(const QJsonArray &o) : QJsonArray(o) {}
    explicit array_type(QJsonArray &&o) : QJsonArray(o) {}
  };

  // Translation between Qt's JSON type and jwt::json::type equivalent
  static jwt::json::type get_type(const value_type &val) {
    using jwt::json::type;

    switch (val.type()) {
    case QJsonValue::Object:
      return type::object;
    case QJsonValue::Array:
      return type::array;
    case QJsonValue::String:
      return type::string;
    case QJsonValue::Double:
      return (std::trunc(val.toDouble()) == val.toDouble()) ? type::integer
                                                            : type::number;
    case QJsonValue::Bool:
      return type::boolean;
    default:
      throw std::logic_error("invalid type");
    }
  }

  // Define conversions to and from std::string to satisfy the requirement
  // static std::string to_std_string(const QString &str) {
  //     return str.toStdString();
  // }

  // static QString from_std_string(const std::string &str) {
  //     return QString::fromStdString(str);
  // }

  // // Helper function for substring to replace std::string::substr
  // static QString substring(const QString &str, integer_type pos, integer_type
  // len) {
  //     return str.mid(pos, len);  // Equivalent to std::string::substr for
  //     QString
  // }

  // // Helper function to concatenate QStrings
  // static QString concat_strings(const QString &lhs, const QString &rhs) {
  //     return lhs + rhs;
  // }

  // Helper function that returns the actual string type to be used in templates
  // where `std::string` is required.
  // static std::string get_compatible_string(const string_type &qtStr) {
  //     return to_std_string(qtStr);
  // }

  // Conversion from generic value to specific type
  static object_type as_object(const value_type &val) {
    if (!val.isObject())
      throw std::logic_error("Not an object type");
    return object_type(val.toObject());
  }

  static array_type as_array(const value_type &val) {
    if (!val.isArray())
      throw std::logic_error("Not an array type");
    return array_type(val.toArray());
  }

  static string_type as_string(const value_type &val) {
    if (!val.isString())
      throw std::logic_error("Not a string type");
    return val.toString().toStdString();
  }

  static number_type as_number(const value_type &val) {
    if (!val.isDouble())
      throw std::logic_error("Not a number type");
    return val.toDouble();
  }

  static integer_type as_integer(const value_type &val) {
    if (!val.isDouble() || std::trunc(val.toDouble()) != val.toDouble())
      throw std::logic_error("Not an integer type");
    return static_cast<integer_type>(val.toDouble());
  }

  static boolean_type as_boolean(const value_type &val) {
    if (!val.isBool())
      throw std::logic_error("Not a boolean type");
    return val.toBool();
  }

  // Serialization and parsing
  static bool parse(value_type &val, const string_type &str) {
    QJsonParseError error;
    QJsonDocument doc =
        QJsonDocument::fromJson(QByteArray::fromStdString(str), &error);
    if (error.error != QJsonParseError::NoError)
      return false;

    if (doc.isObject()) {
      val = value_type(doc.object());
    } else if (doc.isArray()) {
      val = value_type(doc.array());
    } else {
      return false;
    }
    return true;
  }

  static string_type serialize(const value_type &val) {
    QJsonDocument doc;
    if (val.isObject()) {
      doc = QJsonDocument(val.toObject());
    } else if (val.isArray()) {
      doc = QJsonDocument(val.toArray());
    } else {
      throw std::logic_error("Only objects and arrays can be serialized");
    }
    return doc.toJson(QJsonDocument::Compact).toStdString();
  }
};

} // namespace traits

} // namespace jwt

#endif // JWT_CPP_QT_JSON_TRAITS_H
