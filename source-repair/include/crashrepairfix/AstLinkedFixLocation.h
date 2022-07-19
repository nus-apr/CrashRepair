#pragma once

#include "FixLocation.h"
#include "Utils.h"

namespace crashrepairfix {

class AstLinkedFixLocation {
private:
  FixLocation const &fixLocation;
  clang::Stmt *stmt;
  clang::ASTContext &context;
  clang::FunctionDecl const *parentFunction;

  AstLinkedFixLocation(
    FixLocation const &fixLocation,
    clang::Stmt *stmt,
    clang::ASTContext &context,
    clang::FunctionDecl const *parentFunction
  ) : fixLocation(fixLocation),
      stmt(stmt),
      context(context),
      parentFunction(parentFunction)
  {}

public:
  static AstLinkedFixLocation create(
    FixLocation const &fixLocation,
    clang::Stmt *stmt,
    clang::ASTContext &context
  ) {
    auto parentFunction = getParentFunctionDecl(stmt, context);
    return AstLinkedFixLocation(
      fixLocation,
      stmt,
      context,
      parentFunction
    );
  }

  clang::Stmt* getStmt() const {
    return stmt;
  }

  clang::ASTContext const & getContext() const {
    return context;
  }

  clang::FunctionDecl const * getParentFunction() const {
    return parentFunction;
  }

  // TODO expose crash-free condition provided by underlying fix location

  std::string getStmtClassName() const {
    return stmt->getStmtClassName();
  }

  std::string getSource() const {
    return crashrepairfix::getSource(stmt, context);
  }

  FixLocation const & getFixLocation() const {
    return fixLocation;
  }

  Expr const * getConstraint() const {
    return fixLocation.getConstraint();
  }

  SourceLocation const & getLocation() const {
    return fixLocation.getLocation();
  }

  bool isConditionalStmt() const {
    return clang::isa<clang::IfStmt>(stmt)
      || clang::isa<clang::ForStmt>(stmt)
      || clang::isa<clang::WhileStmt>(stmt);
  }

  bool isInsideLoop() const {
    return crashrepairfix::isInsideLoop(stmt, context);
  }

  bool isInsideFunction() const {
    return parentFunction != nullptr;
  }

  bool isInsideVoidFunction() const {
    return isInsideFunction() && parentFunction->getReturnType().getAsString() == "void";
  }
};

}

