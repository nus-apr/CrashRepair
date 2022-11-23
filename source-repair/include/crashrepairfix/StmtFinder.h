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

  clang::ASTContext &context;
  clang::SourceManager &sourceManager;
  crashrepairfix::SourceLocation const &sourceLocation;
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

  std::string getLocationFilename(clang::SourceLocation const &location) {
    auto filename = sourceManager.getFilename(location).str();
    if (relativeToAbsoluteFilenames.find(filename) == relativeToAbsoluteFilenames.end()) {
      relativeToAbsoluteFilenames[filename] = makeAbsolutePath(filename, sourceManager);
    }
    return relativeToAbsoluteFilenames[filename];
  }

  bool VisitBinaryOperator(clang::BinaryOperator *binop) {
    if (checkLocation(binop->getOperatorLoc())) {
      spdlog::debug("found corresponding binary operator!");
      result = binop;
      return false;
    }
    return true;
  }

  bool VisitStmt(clang::Stmt *stmt) {
    if (checkLocation(stmt->getBeginLoc())) {
      spdlog::debug("found corresponding statement!");
      result = stmt;
      return false;
    }
    return true;
  }

private:
  /** Returns true if a given location matches the expected location. */
  bool checkLocation(clang::SourceLocation const &location) {
    if (!location.isValid()) {
      return false;
    }

    std::string locFilename = getLocationFilename(location);
    if (locFilename != sourceLocation.file) {
      return false;
    }

    auto locLine = sourceManager.getSpellingLineNumber(location);
    auto locColumn = sourceManager.getSpellingColumnNumber(location);

    if (locLine == sourceLocation.line) {
      spdlog::info("checking location: {}:{}:{}", locFilename, locLine, locColumn);
    }

    return locColumn == sourceLocation.column && locLine == sourceLocation.line;
  }
};

}
