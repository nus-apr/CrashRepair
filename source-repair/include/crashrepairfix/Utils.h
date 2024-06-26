#pragma once

#include <set>
#include <string>
#include <sstream>
#include <vector>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Lex/Lexer.h>
#include <clang/AST/ASTTypeTraits.h>
#include <clang/AST/ParentMapContext.h>

#include <llvm/ADT/APInt.h>


namespace crashrepairfix {

bool stmtIsBoolExpr(clang::Stmt const *stmt);

clang::SourceLocation findSemiAfterLocation(
  clang::SourceLocation loc,
  clang::ASTContext &Ctx
);

std::string escape_character(char c);

void remove_trailing_newline(std::string &str);

void strip_whitespace(std::string &str);

std::vector<std::string> split(const std::string &s, char delim);

std::string getSource(clang::Stmt const *stmt, clang::SourceManager const &sourceManager);

std::string getSource(clang::Stmt const *stmt, clang::ASTContext const &context);

std::vector<std::string> getLines(std::string const &s);

std::string makeAbsolutePath(std::string const &path, clang::SourceManager const &sourceManager);

clang::SourceRange getRangeWithTokenEnd(clang::SourceRange const &range, clang::ASTContext const &context);
clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::ASTContext const &context);
// clang::SourceRange getRangeWithTokenEnd(clang::SourceRange const &range, clang::SourceManager const &sourceManager);
// clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::SourceManager const &sourceManager);

std::string yesOrNo(bool status);

std::string convertAPIntToString(llvm::APInt const &integer);
std::string convertAPFloatToString(llvm::APFloat const &floating);

bool stmtBelongsToSubtree(clang::Stmt const *stmt, clang::Stmt const *subtree, clang::ASTContext &context);

clang::Stmt const * findTopLevelStmt(clang::Stmt const *stmt, clang::ASTContext &context);

bool isTopLevelStmt(clang::Stmt const *stmt, clang::ASTContext &context);
bool isTopLevelStmt(clang::DynTypedNode const &node, clang::ASTContext &context);

bool containsVarDecl(clang::Stmt const *stmt, clang::ASTContext const &context);

bool isInsideLoop(clang::Stmt const *stmt, clang::ASTContext &context);
bool isInsideLoop(clang::DynTypedNode const &node, clang::ASTContext &context);

bool isInsideSwitch(clang::Stmt const *stmt, clang::ASTContext &context);
bool isInsideSwitch(clang::DynTypedNode const &node, clang::ASTContext &context);

clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::Decl const *decl, clang::ASTContext &context);
clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::DynTypedNode node, clang::ASTContext &context);

clang::FunctionDecl const * getParentFunctionDecl(clang::Stmt const *stmt, clang::ASTContext &context);
clang::FunctionDecl const * getParentFunctionDecl(clang::DynTypedNode node, clang::ASTContext &context);

std::set<clang::VarDecl const *> findReachingVars(clang::Stmt const *stmt, clang::ASTContext &context);
std::set<clang::VarDecl const *> findReachingVars(clang::DynTypedNode node, clang::ASTContext &context);

}
