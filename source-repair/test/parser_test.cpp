#include <gtest/gtest.h>

#include <filesystem>

#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Expr/Parser.h>
#include <crashrepairfix/Expr/ExprToZ3Converter.h>

#include <clang/Tooling/Tooling.h>

namespace fs = std::filesystem;

using namespace crashrepairfix;

TEST(ParserTest, Issue45) {
  // auto constraint = parse("((2147483647 >> @var(integer, x)) < @result(integer)) && ((0 < @var(integer, x)) && (@var(integer, x) < 4))");
  auto constraint = parse("2147483647 >> @var(integer, x)");
  ASSERT_NE(constraint, nullptr);

  z3::context z3c;
  ExprToZ3Converter converter(z3c);
  auto z3Constraint = converter.convert(constraint.get());
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

TEST(ParserTest, Issue44) {
  ASSERT_NE(parse("(-5 + @var(integer, x)) != 0"), nullptr);
}

TEST(ParserTest, Issue25) {
  ASSERT_NE(parse("NULL != @var(pointer, header)"), nullptr);
}

TEST(ParserTest, ShiftRight) {
  ASSERT_NE(parse("INT_MAX >> @var(integer, x)"), nullptr);
}

TEST(ParserTest, ShiftLeft) {
  ASSERT_NE(parse("INT_MAX << @var(integer, x)"), nullptr);
}

TEST(ParserTest, Issue38) {
  ASSERT_NE(parse("((INT_MAX >> @var(integer, x)) < @var(integer, z)) && ((0 < @var(integer, x)) && (@var(integer, x) < 4))"), nullptr);
}

TEST(ParserTest, Issue32) {
  ASSERT_NE(parse("(@var(integer, ++i) < @var(integer, n)) && (0 <= @var(integer, ++i))"), nullptr);
}

TEST(ParserTest, ArrayIndexExpr) {
  ASSERT_NE(parse("(@var(integer, index) < @var(integer, array_0[index]))"), nullptr);
}

TEST(ParserTest, Issue35) {
  ASSERT_NE(parse("(@var(integer, index) < @var(integer, array_0[index])) && (0 <= @var(integer, index))"), nullptr);
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

TEST(ParserTest, Issue57) {
  ASSERT_NE(parse("(0 < (482344960 + @var(integer, x)))"), nullptr);
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

TEST(UtilsTest, WhileLoopTopLevelStmt) {
  auto filename = fs::absolute("test.cpp").string();

  std::string code = R""""(
int main(int argc, const char **argv) {
  int x = 0;
  while (x < 10)
  {
    x++;
    {
      x += 5;
    };
  }
}
  )"""";
  std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code, filename));
  auto &astContext = ast->getASTContext();

  // while stmt
  auto stmt = StmtFinder::find(astContext, SourceLocation(filename, 3, 3));
  ASSERT_NE(stmt, nullptr);
  ASSERT_TRUE(isTopLevelStmt(stmt, astContext));
}

TEST(UtilsTest, ResultConstraintAtValidLocation) {
  auto filename = fs::absolute("test.cpp").string();
  std::string code = R""""(
int main(int argc, const char **argv) {
  char buffer[10];
  int y = buffer[1] + 214748364;
}
  )"""";
  std::unique_ptr<clang::ASTUnit> ast(clang::tooling::buildASTFromCode(code, filename));
  auto &astContext = ast->getASTContext();

  // buffer[1]
  auto stmt = StmtFinder::find(astContext, SourceLocation(filename, 4, 11));
  ASSERT_NE(stmt, nullptr);
  ASSERT_FALSE(isTopLevelStmt(stmt, astContext));

  // buffer[1] + 214748364
  stmt = StmtFinder::find(astContext, SourceLocation(filename, 4, 21));
  ASSERT_NE(stmt, nullptr);
  ASSERT_FALSE(isTopLevelStmt(stmt, astContext));
}

int main(int argc, char **argv) {
  spdlog::set_level(spdlog::level::debug);
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
