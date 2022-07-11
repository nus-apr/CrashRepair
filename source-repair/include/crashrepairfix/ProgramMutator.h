#pragma once

#include <clang/AST/ASTContext.h>

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
};

}
