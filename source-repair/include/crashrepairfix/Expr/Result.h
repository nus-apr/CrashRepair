#pragma once

#include <llvm/Support/raw_ostream.h>

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

  virtual std::string toSource() const override {
    llvm::errs() << "FATAL ERROR: ResultExpr cannot (and should not) be converted to source\n";
    abort();
  }

  /** Writes this expression to a parsable string */
  virtual std::string toString() const override {
    return fmt::format("@result({})", getResultTypeString());
  }

protected:
  Result(ResultType resultType) : Expr(), resultType(resultType) {}

private:
  ResultType resultType;
};

}
