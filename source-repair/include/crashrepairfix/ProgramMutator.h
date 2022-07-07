#pragma once

#include <clang/AST/ASTContext.h>

#include "FixLocalization.h"

namespace crashrepairfix {
  
class ProgramMutator {
public:
  ProgramMutator(FixLocalization &fixLocalization)
  : fixLocalization(fixLocalization) {}

  void mutate(clang::ASTContext &context);
  void mutate(clang::Stmt *stmt, clang::ASTContext &context);

private:
  FixLocalization &fixLocalization;
};

}
