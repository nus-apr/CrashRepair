#include <gtest/gtest.h>

#include <crashrepairfix/Expr/Parser.h>

std::unique_ptr<crashrepairfix::Expr> parse(std::string const &code) {
  return crashrepairfix::parse(code);
}

TEST(ParserTest, VarLessEqConstant) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= 7"), nullptr);
}

TEST(ParserTest, BracketedVarLessEqConstant) {
  ASSERT_NE(parse("(@var(integer, compinfo->height) <= 7)"), nullptr);
}

TEST(ParserTest, VarLessEqVar) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= @var(integer, cmptparm->prec)"), nullptr);
}

TEST(ParserTest, VarLessEqIntMax) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= INT_MAX"), nullptr);
}

TEST(ParserTest, VarLessEqIntMin) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= INT_MIN"), nullptr);
}

TEST(ParserTest, VarLessEqLongMax) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= LONG_MAX"), nullptr);
}

TEST(ParserTest, VarLessEqLongMin) {
  ASSERT_NE(parse("@var(integer, compinfo->height) <= LONG_MIN"), nullptr);
}

TEST(ParserTest, Issue16) {
  ASSERT_NE(parse("((@var(integer, compinfo->width) * @var(integer, compinfo->height)) <= (LONG_MAX / (@var(integer, cmptparm->prec) + 7)))"), nullptr);
}
