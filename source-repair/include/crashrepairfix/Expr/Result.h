#pragma once

#include "Expr.h"

namespace crashrepairfix {

class Result : public Expr {
public:
  Expr::Kind getExprKind() const override {
    return Expr::Kind::Result;
  }

  virtual ResultType getResultType() const override {
    return resultType;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(resultType);
  }

  static std::unique_ptr<Result> create(ResultType resultType) {
    return std::unique_ptr<Result>(new Result(resultType));
  }

protected:
  Result(ResultType resultType) : Expr(), resultType(resultType) {}

private:
  ResultType resultType;
};

}
