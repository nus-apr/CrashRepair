#pragma once

#include <fstream>

#include <clang/AST/LexicallyOrderedRecursiveASTVisitor.h>

#include <spdlog/spdlog.h>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"

namespace crashrepairfix {

class StmtFinder
  : public clang::LexicallyOrderedRecursiveASTVisitor<StmtFinder> {
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
  std::unordered_map<std::string, std::string> relativeToAbsoluteFilenames;

  explicit StmtFinder(clang::ASTContext &context, SourceLocation const &sourceLocation)
    : LexicallyOrderedRecursiveASTVisitor(context.getSourceManager()),
      context(context),
      sourceManager(context.getSourceManager()),
      sourceLocation(sourceLocation),
      result(nullptr),
      relativeToAbsoluteFilenames()
    {}

  std::string getStmtFilename(clang::Stmt const *stmt) {
    auto filename = sourceManager.getFilename(stmt->getBeginLoc()).str();
    if (relativeToAbsoluteFilenames.find(filename) == relativeToAbsoluteFilenames.end()) {
      relativeToAbsoluteFilenames[filename] = makeAbsolutePath(filename, sourceManager);
    }
    return relativeToAbsoluteFilenames[filename];
  }

  bool VisitStmt(clang::Stmt *stmt) {
    auto stmtLoc = stmt->getBeginLoc();
    if (!stmtLoc.isValid()) {
      return true;
    }

    std::string stmtFilename = getStmtFilename(stmt);
    if (stmtFilename != sourceLocation.file) {
      return true;
    }

    auto stmtLine = sourceManager.getSpellingLineNumber(stmtLoc);
    auto stmtColumn = sourceManager.getSpellingColumnNumber(stmtLoc);

    spdlog::debug("stmt at: {}:{}:{}", stmtFilename, stmtLine, stmtColumn);

    // we have a match! store it and stop searching
    if (stmtColumn == sourceLocation.column && stmtLine == sourceLocation.line) {
      result = stmt;
      return false;
    }
 
    return true;
  }
};

}
