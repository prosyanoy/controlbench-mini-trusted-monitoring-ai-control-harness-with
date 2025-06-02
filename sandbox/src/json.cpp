#include "cbsandbox/json.hpp"

#include <cmath>
#include <cstdio>
#include <cerrno>
#include <cstdlib>

namespace cb {

bool Json::as_bool() const {
  if (type_ != Type::Bool) throw JsonError("expected bool");
  return b_;
}
int64_t Json::as_int() const {
  if (type_ == Type::Int) return i_;
  if (type_ == Type::Double) return static_cast<int64_t>(d_);
  throw JsonError("expected number");
}
double Json::as_double() const {
  if (type_ == Type::Double) return d_;
  if (type_ == Type::Int) return static_cast<double>(i_);
  throw JsonError("expected number");
}
const std::string& Json::as_string() const {
  if (type_ != Type::String) throw JsonError("expected string");
  return s_;
}
const Json::Array& Json::as_array() const {
  if (type_ != Type::Array) throw JsonError("expected array");
  return a_;
}
const Json::Object& Json::as_object() const {
  if (type_ != Type::Object) throw JsonError("expected object");
  return o_;
}

const Json* Json::find(const std::string& key) const {
  if (type_ != Type::Object) return nullptr;
  for (const auto& m : o_)
    if (m.first == key) return &m.second;
  return nullptr;
}

void Json::set(const std::string& key, Json value) {
  if (type_ == Type::Null) type_ = Type::Object;
  if (type_ != Type::Object) throw JsonError("set on non-object");
  for (auto& m : o_) {
    if (m.first == key) {
      m.second = std::move(value);
      return;
    }
  }
  o_.emplace_back(key, std::move(value));
}

void Json::push(Json value) {
  if (type_ == Type::Null) type_ = Type::Array;
  if (type_ != Type::Array) throw JsonError("push on non-array");
  a_.push_back(std::move(value));
}

// ---------------------------------------------------------------- serializer

void append_json_string(std::string& out, const std::string& s) {
  static const char* hex = "0123456789abcdef";
  out.push_back('"');
  size_t i = 0;
  const size_t n = s.size();
  while (i < n) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) {
      switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
          if (c < 0x20 || c == 0x7f) {
            out += "\\u00";
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
          } else {
            out.push_back(static_cast<char>(c));
          }
      }
      ++i;
      continue;
    }
    // Multi-byte UTF-8: validate, otherwise substitute U+FFFD.
    int len = 0;
    uint32_t cp = 0;
    if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
    bool ok = len > 0 && i + len <= n;
    if (ok) {
      for (int k = 1; k < len; ++k) {
        unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80) { ok = false; break; }
        cp = (cp << 6) | (cc & 0x3F);
      }
    }
    if (ok) {
      static const uint32_t min_cp[5] = {0, 0, 0x80, 0x800, 0x10000};
      if (cp < min_cp[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) ok = false;
    }
    if (ok) {
      out.append(s, i, len);
      i += len;
    } else {
      out += "\xEF\xBF\xBD";
      ++i;
    }
  }
  out.push_back('"');
}

void Json::dump_to(std::string& out) const {
  switch (type_) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += b_ ? "true" : "false"; break;
    case Type::Int: out += std::to_string(i_); break;
    case Type::Double: {
      if (!std::isfinite(d_)) { out += "null"; break; }
      char buf[40];
      std::snprintf(buf, sizeof buf, "%.17g", d_);
      out += buf;
      break;
    }
    case Type::String: append_json_string(out, s_); break;
    case Type::Array: {
      out.push_back('[');
      for (size_t k = 0; k < a_.size(); ++k) {
        if (k) out.push_back(',');
        a_[k].dump_to(out);
      }
      out.push_back(']');
      break;
    }
    case Type::Object: {
      out.push_back('{');
      for (size_t k = 0; k < o_.size(); ++k) {
        if (k) out.push_back(',');
        append_json_string(out, o_[k].first);
        out.push_back(':');
        o_[k].second.dump_to(out);
      }
      out.push_back('}');
      break;
    }
  }
}

std::string Json::dump() const {
  std::string out;
  dump_to(out);
  return out;
}

// -------------------------------------------------------------------- parser

namespace {

class Parser {
 public:
  explicit Parser(const std::string& t) : t_(t) {}

  Json parse_document() {
    skip_ws();
    Json v = parse_value(0);
    skip_ws();
    if (pos_ != t_.size()) fail("trailing characters");
    return v;
  }

 private:
  [[noreturn]] void fail(const std::string& msg) const {
    throw JsonError("JSON parse error at offset " + std::to_string(pos_) + ": " + msg);
  }
  void skip_ws() {
    while (pos_ < t_.size() &&
           (t_[pos_] == ' ' || t_[pos_] == '\t' || t_[pos_] == '\n' || t_[pos_] == '\r'))
      ++pos_;
  }
  char peek() const { return pos_ < t_.size() ? t_[pos_] : '\0'; }
  bool consume(const char* lit) {
    size_t n = std::char_traits<char>::length(lit);
    if (t_.compare(pos_, n, lit) == 0) {
      pos_ += n;
      return true;
    }
    return false;
  }

  Json parse_value(int depth) {
    if (depth > 64) fail("nesting too deep");
    char c = peek();
    if (c == '{') return parse_object(depth);
    if (c == '[') return parse_array(depth);
    if (c == '"') return Json(parse_string());
    if (consume("true")) return Json(true);
    if (consume("false")) return Json(false);
    if (consume("null")) return Json();
    if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
    fail("unexpected character");
  }

  Json parse_object(int depth) {
    ++pos_;
    Json obj = Json::object();
    skip_ws();
    if (peek() == '}') { ++pos_; return obj; }
    while (true) {
      skip_ws();
      if (peek() != '"') fail("expected string key");
      std::string key = parse_string();
      skip_ws();
      if (peek() != ':') fail("expected ':'");
      ++pos_;
      skip_ws();
      obj.set(key, parse_value(depth + 1));
      skip_ws();
      if (peek() == ',') { ++pos_; continue; }
      if (peek() == '}') { ++pos_; return obj; }
      fail("expected ',' or '}'");
    }
  }

  Json parse_array(int depth) {
    ++pos_;
    Json arr = Json::array();
    skip_ws();
    if (peek() == ']') { ++pos_; return arr; }
    while (true) {
      skip_ws();
      arr.push(parse_value(depth + 1));
      skip_ws();
      if (peek() == ',') { ++pos_; continue; }
      if (peek() == ']') { ++pos_; return arr; }
      fail("expected ',' or ']'");
    }
  }

  unsigned parse_hex4() {
    if (pos_ + 4 > t_.size()) fail("truncated \\u escape");
    unsigned v = 0;
    for (int k = 0; k < 4; ++k) {
      char c = t_[pos_++];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= c - '0';
      else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
      else fail("bad hex digit");
    }
    return v;
  }

  static void put_utf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) out.push_back(static_cast<char>(cp));
    else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  std::string parse_string() {
    ++pos_;  // opening quote
    std::string out;
    while (true) {
      if (pos_ >= t_.size()) fail("unterminated string");
      char c = t_[pos_++];
      if (c == '"') return out;
      if (static_cast<unsigned char>(c) < 0x20) fail("control character in string");
      if (c != '\\') { out.push_back(c); continue; }
      if (pos_ >= t_.size()) fail("unterminated escape");
      char e = t_[pos_++];
      switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u': {
          uint32_t cp = parse_hex4();
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (!consume("\\u")) fail("lone high surrogate");
            uint32_t lo = parse_hex4();
            if (lo < 0xDC00 || lo > 0xDFFF) fail("bad low surrogate");
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            fail("lone low surrogate");
          }
          put_utf8(out, cp);
          break;
        }
        default: fail("bad escape");
      }
    }
  }

  Json parse_number() {
    size_t start = pos_;
    if (peek() == '-') ++pos_;
    bool is_float = false;
    while (pos_ < t_.size()) {
      char c = t_[pos_];
      if (c >= '0' && c <= '9') { ++pos_; }
      else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { is_float = true; ++pos_; }
      else break;
    }
    std::string tok = t_.substr(start, pos_ - start);
    if (tok.empty() || tok == "-") fail("bad number");
    char* end = nullptr;
    if (!is_float) {
      errno = 0;
      long long v = std::strtoll(tok.c_str(), &end, 10);
      if (errno == 0 && end && *end == '\0') return Json(static_cast<int64_t>(v));
    }
    double d = std::strtod(tok.c_str(), &end);
    if (!end || *end != '\0') fail("bad number");
    return Json(d);
  }

  const std::string& t_;
  size_t pos_ = 0;
};

}  // namespace

Json Json::parse(const std::string& text) { return Parser(text).parse_document(); }

}  // namespace cb
