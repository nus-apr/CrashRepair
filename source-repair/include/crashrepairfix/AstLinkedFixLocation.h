#pragma once

#include "FixLocation.h"
#include "Utils.h"

namespace crashrepairfix {

class AstLinkedFixLocation {
private:
  FixLocation const &fixLocation;
  clang::Stmt *stmt;
  clang::ASTContext &context;

  AstLinkedFixLocation(
    FixLocation const &fixLocation,
    clang::Stmt *stmt,
    clang::ASTContext &context
  ) : fixLocation(fixLocation), stmt(stmt), context(context) {}

public:
  static AstLinkedFixLocation create(
    FixLocation const &fixLocation,
    clang::Stmt *stmt,
    clang::ASTContext &context
  ) {
    return AstLinkedFixLocation(
      fixLocation,
      stmt,
      context
    );
  }

  clang::Stmt* getStmt() const {
    return stmt;
  }

  std::string getStmtClassName() const {
    return stmt->getStmtClassName();
  }

  std::string getSource() const {
    return crashrepairfix::getSource(stmt, context);
  }

  FixLocation const & getFixLocation() const {
    return fixLocation;
  }

  SourceLocation const & getLocation() const {
    return fixLocation.getLocation();
  }

  bool isInsideLoop() const {
    return crashrepairfix::isInsideLoop(stmt, context);
  }
};

}

