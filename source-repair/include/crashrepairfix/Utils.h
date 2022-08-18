#pragma once

#include <string>
#include <sstream>
#include <vector>

#include <clang/AST/ASTContext.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Lex/Lexer.h>
#include <clang/AST/ASTTypeTraits.h>
#include <clang/AST/ParentMapContext.h>

namespace crashrepairfix {

std::vector<std::string> split(const std::string &s, char delim);

std::string getSource(clang::Stmt const *stmt, clang::SourceManager const &sourceManager);

std::string getSource(clang::Stmt const *stmt, clang::ASTContext const &context);

std::vector<std::string> getLines(std::string const &s);

std::string makeAbsolutePath(std::string const &path, clang::SourceManager const &sourceManager);

clang::SourceRange getRangeWithTokenEnd(clang::SourceRange const &range, clang::SourceManager const &sourceManager);
clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::ASTContext const &context);
clang::SourceRange getRangeWithTokenEnd(clang::Stmt const *stmt, clang::SourceManager const &sourceManager);

std::string yesOrNo(bool status);

bool isTopLevelStmt(clang::Stmt const *stmt, clang::ASTContext &context);
bool isTopLevelStmt(clang::DynTypedNode const &node, clang::ASTContext &context);

bool isInsideLoop(clang::Stmt const *stmt, clang::ASTContext &context);
bool isInsideLoop(clang::DynTypedNode const &node, clang::ASTContext &context);

clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::Decl const *decl, clang::ASTContext &context);
clang::TranslationUnitDecl const * getParentTranslationUnitDecl(clang::DynTypedNode node, clang::ASTContext &context);

clang::FunctionDecl const * getParentFunctionDecl(clang::Stmt const *stmt, clang::ASTContext &context);
clang::FunctionDecl const * getParentFunctionDecl(clang::DynTypedNode node, clang::ASTContext &context);

}
