#include <gtest/gtest.h>

#include <filesystem>

#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Expr/Parser.h>

#include <clang/Tooling/Tooling.h>

namespace fs = std::filesystem;

using namespace crashrepairfix;

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

TEST(ParserTest, Issue25) {
  ASSERT_NE(parse("NULL != @var(pointer, header)"), nullptr);
}

TEST(ParserTest, Issue32) {
  ASSERT_NE(parse("(@var(integer, ++i) < @var(integer, n)) && (0 <= @var(integer, ++i))"), nullptr);
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

// https://stackoverflow.com/questions/37276015/how-do-i-generate-an-ast-from-a-string-of-c-using-clang
TEST(UtilsTest, ForLoopTopLevelStmt) {
  auto filename = fs::absolute("test.cpp").string();

  std::string code = R""""(
int main(int argc, const char **argv) {
  int x = 0;
  for (int i = 0; i < 10; i++) {
    x += i;
  }
}
  )"""";
  std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code, filename));
  auto &astContext = ast->getASTContext();

  // loop guard: i < 10
  auto stmt = StmtFinder::find(astContext, SourceLocation(filename, 4, 21));
  ASSERT_NE(stmt, nullptr);
  ASSERT_FALSE(isTopLevelStmt(stmt, astContext));

  // x += i;
  stmt = StmtFinder::find(astContext, SourceLocation(filename, 5, 7));
  ASSERT_NE(stmt, nullptr);
  ASSERT_TRUE(isTopLevelStmt(stmt, astContext));
}
