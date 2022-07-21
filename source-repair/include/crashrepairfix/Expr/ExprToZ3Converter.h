#pragma once

#include <z3++.h>

#include "Exprs.h"

namespace crashrepairfix {

class ExprToZ3Converter {
public:
  ExprToZ3Converter(z3::context &z3c) : z3c(z3c) {}
  ~ExprToZ3Converter(){}

  z3::expr convert(Expr const *expr);

private:
  [[maybe_unused]] z3::context &z3c;

  z3::expr convert(BinOp const *expr);
  z3::expr convert(UnaryOp const *expr);
  z3::expr convert(IntConst const *expr);
  z3::expr convert(FloatConst const *expr);
  z3::expr convert(NullConst const *expr);
  z3::expr convert(Result const *expr);
  z3::expr convert(Var const *expr);
};

}
