#pragma once

#include <unordered_set>
#include <vector>

namespace crashrepairfix {

class Var;

enum class ResultType {
  Int,
  Float,
  Pointer,
};

class Expr {
public:
  enum class Kind {
    BinOp,
    UnaryOp,
    FloatConst,
    IntConst,
    NullConst,
    Var,
    Result
  };

  virtual ~Expr(){}

  /** Returns the set of vars that are used within this expression. */
  virtual std::unordered_set<Var const *> vars() const = 0;

  /** Returns the size of this expression subtree. */
  virtual size_t size() const = 0;

  /** Returns the immediate children in this expression subtree. */
  virtual std::vector<Expr const *> children() const = 0;
  virtual std::vector<Expr *> children() = 0;

  /** Returns a deep copy of this expression. */
  virtual Expr* copy() const = 0;

  /** Returns the kind of this expression */
  virtual Kind getExprKind() const = 0;
};

}
