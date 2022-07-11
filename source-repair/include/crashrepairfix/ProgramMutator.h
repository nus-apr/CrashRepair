#pragma once

#include <clang/AST/ASTContext.h>

#include "AstLinkedFixLocation.h"
#include "FixLocalization.h"
#include "Mutation.h"

namespace crashrepairfix {
  
class ProgramMutator {
public:
  ProgramMutator(FixLocalization &fixLocalization)
  : fixLocalization(fixLocalization), mutations() {}

  void mutate(clang::ASTContext &context);
  void mutate(clang::Stmt *stmt, clang::ASTContext &context);

  void save();

private:
  FixLocalization &fixLocalization;
  std::vector<Mutation> mutations;

  void mutateConditionalStmt(clang::Stmt *stmt, clang::ASTContext &context);
  void mutateNonConditionalStmt(clang::Stmt *stmt, clang::ASTContext &context);
  void prependConditionalControlFlow(clang::Stmt *stmt, clang::ASTContext &context);
  void guardStatement(clang::Stmt *stmt, clang::ASTContext &context);
  void addConditionalBreak(clang::Stmt *stmt, clang::ASTContext &context);
  void addConditionalContinue(clang::Stmt *stmt, clang::ASTContext &context);
  void addConditionalReturn(clang::Stmt *stmt, clang::ASTContext &context);
  void addConditionalVoidReturn(clang::Stmt *stmt, clang::ASTContext &context);
};

}
