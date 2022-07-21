#pragma once

#include <memory>
#include <string>
#include <vector>

#include "Edit.h"

namespace crashrepairfix {

class ExprMutator {
public:
  virtual ~ExprMutator(){}

  virtual std::string getName() const = 0;

  /**
   * Generates edits of a given expression using this mutator and saves them to
   * a given output.
   */
  virtual void generate(Expr const *expr, std::vector<std::unique_ptr<ExprEdit>> &edits) = 0;
};

}
