// Minimal JSON value, parser and serializer (enough for the job protocol).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace cb {

class JsonError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Json {
 public:
  enum class Type { Null, Bool, Int, Double, String, Array, Object };
  using Array = std::vector<Json>;
  using Member = std::pair<std::string, Json>;
  using Object = std::vector<Member>;  // insertion ordered

  Json() = default;
  Json(bool b) : type_(Type::Bool), b_(b) {}
  Json(int v) : type_(Type::Int), i_(v) {}
  Json(int64_t v) : type_(Type::Int), i_(v) {}
  Json(uint64_t v) : type_(Type::Int), i_(static_cast<int64_t>(v)) {}
  Json(double v) : type_(Type::Double), d_(v) {}
  Json(const char* s) : type_(Type::String), s_(s) {}
  Json(std::string s) : type_(Type::String), s_(std::move(s)) {}
  Json(Array a) : type_(Type::Array), a_(std::move(a)) {}
  Json(Object o) : type_(Type::Object), o_(std::move(o)) {}

  static Json array() { return Json(Array{}); }
  static Json object() { return Json(Object{}); }

  Type type() const { return type_; }
  bool is_null() const { return type_ == Type::Null; }
  bool is_object() const { return type_ == Type::Object; }
  bool is_array() const { return type_ == Type::Array; }
  bool is_string() const { return type_ == Type::String; }
  bool is_number() const { return type_ == Type::Int || type_ == Type::Double; }

  bool as_bool() const;
  int64_t as_int() const;
  double as_double() const;
  const std::string& as_string() const;
  const Array& as_array() const;
  const Object& as_object() const;

  // Object helpers.
  const Json* find(const std::string& key) const;
  void set(const std::string& key, Json value);
  // Array helper.
  void push(Json value);

  std::string dump() const;
  static Json parse(const std::string& text);

 private:
  void dump_to(std::string& out) const;

  Type type_ = Type::Null;
  bool b_ = false;
  int64_t i_ = 0;
  double d_ = 0.0;
  std::string s_;
  Array a_;
  Object o_;
};

// Appends s as a JSON string literal; invalid UTF-8 bytes become U+FFFD.
void append_json_string(std::string& out, const std::string& s);

}  // namespace cb
