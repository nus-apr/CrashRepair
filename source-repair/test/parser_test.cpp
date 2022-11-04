#include <gtest/gtest.h>

#include <crashrepairfix/Expr/Parser.h>

std::unique_ptr<crashrepairfix::Expr> parse(std::string const &code) {
  return crashrepairfix::parse(code);
}

TEST(ParserTest, HandlesLongMax) {
  ASSERT_NE(parse("(LONG_MAX < 0)"), nullptr);
}
