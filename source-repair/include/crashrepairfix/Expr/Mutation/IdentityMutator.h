#pragma once

#include "Mutator.h"

namespace crashrepairfix {

class ExprIdentityMutator : public ExprMutator {
public:
  ExprIdentityMutator(){}
  ~ExprIdentityMutator(){}

  std::string getName() const override {
    return "identity";
  }

  void generate(Expr const *expr, std::vector<std::unique_ptr<ExprEdit>> &edits) override {
    edits.emplace_back(std::make_unique<Edit>());
  }

private:
  class Edit : public ExprEdit {
  public:
    Edit(){}
    ~Edit(){}
    void apply(Expr* expr) const override {
      return;
    }
  };
};

}
