#pragma once

#include "Mutator.h"
#include "../BinOp.h"
#include "../../ProgramStates.h"

namespace crashrepairfix {

class ReplaceVarRefMutator : public ExprMutator {
public:
  ReplaceVarRefMutator(std::vector<std::unique_ptr<ProgramStates::Variable>> const &variables) : typeToVariables() {
    typeToVariables[ResultType::Int] = {};
    typeToVariables[ResultType::Float] = {};
    typeToVariables[ResultType::Pointer] = {};
    for (auto &variable : variables) {
      typeToVariables[variable->getResultType()].push_back(variable.get());
    }
  }
  ReplaceVarRefMutator(ProgramStates const &states) : ReplaceVarRefMutator(states.getVariables()) {}
  ~ReplaceVarRefMutator(){}

  std::string getName() const override {
    return "replace-varref";
  }

  void generate(Expr const *expr, std::vector<std::unique_ptr<ExprEdit>> &edits) override {
    if (expr->getExprKind() != Expr::Kind::Var) {
      return;
    }

    auto originalVariable = static_cast<Var const *>(expr);
    for (auto &replacementVariable : typeToVariables[expr->getResultType()]) {
      if (originalVariable->getName() == replacementVariable->getName()) {
        continue;
      }
      edits.push_back(std::make_unique<Edit>(replacementVariable));
    }
  }

private:
  std::unordered_map<ResultType, std::vector<ProgramStates::Variable const *>> typeToVariables;

  class Edit : public ExprEdit {
  public:
    void apply(Expr* expr) const override {
      static_cast<Var *>(expr)->setName(variable->getName());
    }

    Edit(ProgramStates::Variable const *variable) : variable(variable) {}
    ~Edit(){}

  private:
    ProgramStates::Variable const *variable;
  };
};

}
