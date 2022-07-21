#pragma once

#include "../Expr.h"

namespace crashrepairfix {

class ExprEdit {
public:
  virtual ~ExprEdit(){}

  // destructively applies this edit at a given expression
  virtual void apply(Expr *expr) const = 0;
};

}
