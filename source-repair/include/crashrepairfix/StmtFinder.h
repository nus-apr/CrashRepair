#pragma once

#include <fstream>

#include <clang/AST/RecursiveASTVisitor.h>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"

namespace crashrepairfix {

class StmtFinder
  : public clang::RecursiveASTVisitor<StmtFinder> {
public:
  static clang::Stmt* find(clang::ASTContext &context, SourceLocation const &sourceLocation) {
    StmtFinder finder(context, sourceLocation);
    finder.TraverseAST(context);
    return finder.result;
  }

  [[maybe_unused]] clang::ASTContext &context;
  [[maybe_unused]] clang::SourceManager &sourceManager;
  [[maybe_unused]] crashrepairfix::SourceLocation const &sourceLocation;
  clang::Stmt *result;

  explicit StmtFinder(clang::ASTContext &context, SourceLocation const &sourceLocation)
    : context(context),
      sourceManager(context.getSourceManager()),
      sourceLocation(sourceLocation),
      result(nullptr)
    {}


  bool VisitStmt(clang::Stmt *stmt) {
    auto stmtLoc = stmt->getBeginLoc();
    if (!stmtLoc.isValid()) {
      return true;
    }

    // TODO ensure that stmt is in the correct file before getting here
    // TODO normalize filename
    std::string stmtFilename = sourceManager.getFilename(stmtLoc).str();
    if (stmtFilename != sourceLocation.file) {
      return true;
    }

    auto stmtLine = sourceManager.getSpellingLineNumber(stmtLoc);
    auto stmtColumn = sourceManager.getSpellingColumnNumber(stmtLoc);
    // spdlog::info("stmt at {}:{}", stmtLine, stmtColumn);

    // we have a match! store it and stop searching
    if (stmtColumn == sourceLocation.column && stmtLine == sourceLocation.line) {
      result = stmt;
      return false;
    }
 
    return true;
  }
};

}
