#pragma once

#include <string>

#include <clang/AST/ASTContext.h>

#include "AstLinkedFixLocation.h"
#include "DiffGenerator.h"
#include "FixLocalization.h"
#include "FixLocationLinter.h"
#include "Mutation.h"

namespace crashrepairfix {

class ProgramMutator {
public:
  ProgramMutator(FixLocalization &fixLocalization, std::string const &saveToFilename)
  : diffGenerator(), linter(fixLocalization, false), fixLocalization(fixLocalization), saveToFilename(saveToFilename), mutations() {}

  void mutate(clang::ASTContext &context);
  void mutate(AstLinkedFixLocation &location);

  void save();

private:
  DiffGenerator diffGenerator;
  FixLocationLinter linter;
  FixLocalization &fixLocalization;
  std::string saveToFilename;
  std::vector<Mutation> mutations;

  void create(Operator op, AstLinkedFixLocation &location, std::vector<Replacement> const &replacements);

  void mutateExprStmt(AstLinkedFixLocation &location);
  void mutateConditionalStmt(AstLinkedFixLocation &location);
  void mutateNonConditionalStmt(AstLinkedFixLocation &location);
  void prependConditionalControlFlow(AstLinkedFixLocation &location);
  void strengthenBranchCondition(AstLinkedFixLocation &location);
  void guardStatement(AstLinkedFixLocation &location);
  void addConditional(AstLinkedFixLocation &location, std::string const &bodySource);
  void addConditionalBreak(AstLinkedFixLocation &location);
  void addConditionalContinue(AstLinkedFixLocation &location);
  void addConditionalReturn(AstLinkedFixLocation &location);
  void addConditionalVoidReturn(AstLinkedFixLocation &location);
  void addConditionalNonVoidReturn(AstLinkedFixLocation &location);
};

}
