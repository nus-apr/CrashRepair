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

std::string yesOrNo(bool status);

bool isInsideLoop(clang::Stmt const *stmt, clang::ASTContext &context);
bool isInsideLoop(clang::DynTypedNode const &node, clang::ASTContext &context);

}
