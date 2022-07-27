#pragma once

#include "Expr.h"
#include "ExprToZ3Converter.h"
#include "Mutation/Mutations.h"
#include "../ProgramStates.h"

namespace crashrepairfix {

class ExprGenerator {
public:
  ExprGenerator(
    Expr const *expr,
    Expr const *constraint,
    ProgramStates const &states,
    size_t maxEdits = 3
  ) : expr(expr), constraint(constraint), states(states), maxEdits(maxEdits) {

  }
  ~ExprGenerator(){}

  std::vector<std::unique_ptr<Expr>> generate(size_t limit = 15) const;

private:
  Expr const *expr;
  Expr const *constraint;
  ProgramStates const &states;
  size_t maxEdits;
};

}
