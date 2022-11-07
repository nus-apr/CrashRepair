#pragma once

#include <clang/AST/LexicallyOrderedRecursiveASTVisitor.h>

namespace crashrepairfix {

class DescendantChecker
  : public clang::LexicallyOrderedRecursiveASTVisitor<DescendantChecker> {
public:
  clang::Stmt const *searchStmt;
  bool found;

  static bool subtreeContainsStmt(clang::ASTContext &context, clang::Stmt const *subtree, clang::Stmt const *stmt) {
    DescendantChecker checker(context, stmt);
    checker.TraverseStmt(const_cast<clang::Stmt*>(subtree));
    return checker.found;
  }

  explicit DescendantChecker(clang::ASTContext &context, clang::Stmt const *searchStmt)
    : LexicallyOrderedRecursiveASTVisitor(context.getSourceManager()),
      searchStmt(searchStmt),
      found(false)
    {}

  bool VisitStmt(clang::Stmt *stmt) {
    if (stmt == searchStmt) {
      found = true;
      return false;
    }
    return true;
  }
};

}
