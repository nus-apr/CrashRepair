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
