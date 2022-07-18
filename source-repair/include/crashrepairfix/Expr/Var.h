#pragma once

#include "Expr.h"

namespace crashrepairfix {

class Var : public Expr {
public:
  virtual Kind getExprKind() const override {
    return Expr::Kind::Var;
  }

  std::string const & getName() const {
    return name;
  }

  virtual ResultType getResultType() const override {
    return resultType;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(name, resultType);
  }

  static std::unique_ptr<Var> create(std::string const &name, ResultType resultType) {
    return std::unique_ptr<Var>(new Var(name, resultType));
  }

protected:
  Var(std::string const &name, ResultType resultType)
  : Expr(), name(name), resultType(resultType)
  {}

private:
  std::string name;
  ResultType resultType;
};

}
