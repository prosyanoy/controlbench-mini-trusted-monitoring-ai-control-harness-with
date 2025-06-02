#include <gtest/gtest.h>

#include "cbsandbox/json.hpp"

using cb::Json;

TEST(Json, ParsesNestedDocument) {
  Json j = Json::parse(R"({"a":[1,2.5,true,null,"x"],"b":{"c":"d"}})");
  ASSERT_TRUE(j.is_object());
  const auto& a = j.find("a")->as_array();
  EXPECT_EQ(a[0].as_int(), 1);
  EXPECT_DOUBLE_EQ(a[1].as_double(), 2.5);
  EXPECT_TRUE(a[2].as_bool());
  EXPECT_TRUE(a[3].is_null());
  EXPECT_EQ(a[4].as_string(), "x");
  EXPECT_EQ(j.find("b")->find("c")->as_string(), "d");
}

TEST(Json, RoundTripsEscapesAndUnicode) {
  Json j = Json::parse(R"("line\nbreak \"q\" \u00e9 \ud83d\ude00 \u0001")");
  EXPECT_EQ(j.as_string(), "line\nbreak \"q\" \xC3\xA9 \xF0\x9F\x98\x80 \x01");
  Json again = Json::parse(j.dump());
  EXPECT_EQ(again.as_string(), j.as_string());
}

TEST(Json, InvalidUtf8IsReplacedWhenSerializing) {
  std::string s = "ok\xff\xfe";
  std::string out = Json(s).dump();
  EXPECT_EQ(out, "\"ok\xEF\xBF\xBD\xEF\xBF\xBD\"");
  EXPECT_NO_THROW(Json::parse(out));
}

TEST(Json, RejectsMalformedInput) {
  for (const char* bad : {"", "{", "[1,]", "{\"a\" 1}", "\"abc", "tru", "[1] x", "\"\\ud800\"", "01x"})
    EXPECT_THROW(Json::parse(bad), cb::JsonError) << bad;
}

TEST(Json, RejectsExcessiveNesting) {
  std::string deep(200, '[');
  deep += std::string(200, ']');
  EXPECT_THROW(Json::parse(deep), cb::JsonError);
}

TEST(Json, ObjectKeepsInsertionOrderAndOverwrites) {
  Json o = Json::object();
  o.set("z", 1);
  o.set("a", 2);
  o.set("z", 3);
  EXPECT_EQ(o.dump(), R"({"z":3,"a":2})");
}
