#pragma once

#include <spdlog/fmt/fmt.h>

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

  virtual std::string toString() const override {
    return fmt::format(
      "var({}, {})",
      getResultTypeString(),
      name
    );
  }

  virtual std::string toSource() const override {
    return name;
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
