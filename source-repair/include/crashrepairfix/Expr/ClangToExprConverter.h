#pragma once

#include <clang/AST/ASTContext.h>

#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>

#include "Exprs.h"
#include "../Utils.h"

namespace crashrepairfix {

class ClangToExprConverter {
public:
  ClangToExprConverter(clang::ASTContext const &context)
  : context(context), sourceManager(context.getSourceManager()) {}

  std::unique_ptr<Expr> convert(clang::Stmt const *stmt) const;
  std::unique_ptr<Expr> convert(clang::Expr const *clangExpr) const;

private:
  [[maybe_unused]] clang::ASTContext const &context;
  [[maybe_unused]] clang::SourceManager const &sourceManager;

  std::string getSource(clang::Stmt const *stmt) const;

  std::unique_ptr<Expr> convert(clang::ParenExpr const *parenExpr) const;
  std::unique_ptr<Expr> convert(clang::IntegerLiteral const *literal) const;
  std::unique_ptr<Expr> convert(clang::FloatingLiteral const *literal) const;
  std::unique_ptr<Expr> convert(clang::BinaryOperator const *binOp) const;
  std::unique_ptr<Expr> convert(clang::DeclRefExpr const *declRefExpr) const;
};

}
