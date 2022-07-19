#pragma once

#include <clang/AST/ASTContext.h>

#include "AstLinkedFixLocation.h"
#include "DiffGenerator.h"
#include "FixLocalization.h"
#include "Mutation.h"

namespace crashrepairfix {
  
class ProgramMutator {
public:
  ProgramMutator(FixLocalization &fixLocalization)
  : diffGenerator(), fixLocalization(fixLocalization), mutations() {}

  void mutate(clang::ASTContext &context);
  void mutate(AstLinkedFixLocation &location);

  void save();

private:
  DiffGenerator diffGenerator;
  FixLocalization &fixLocalization;
  std::vector<Mutation> mutations;

  void create(AstLinkedFixLocation &location, std::vector<Replacement> const &replacements);

  void mutateConditionalStmt(AstLinkedFixLocation &location);
  void mutateNonConditionalStmt(AstLinkedFixLocation &location);
  void prependConditionalControlFlow(AstLinkedFixLocation &location);
  void guardStatement(AstLinkedFixLocation &location);
  void addConditional(AstLinkedFixLocation &location, std::string const &bodySource);
  void addConditionalBreak(AstLinkedFixLocation &location);
  void addConditionalContinue(AstLinkedFixLocation &location);
  void addConditionalReturn(AstLinkedFixLocation &location);
  void addConditionalVoidReturn(AstLinkedFixLocation &location);
  void addConditionalNonVoidReturn(AstLinkedFixLocation &location);
};

}
