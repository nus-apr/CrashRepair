#pragma once

#include "Expr.h"

namespace crashrepairfix {

class BinOp : public Expr {
public:
  enum class Opcode {
    LT,
    LTE,
    GT,
    GTE,
    EQ,
    NEQ,
    AND,
    OR,
    ADD,
    SUBTRACT,
    DIVIDE,
    MULTIPLY,
  };

  Expr::Kind getExprKind() const override {
    return Expr::Kind::BinOp;
  }

  Opcode getOpcode() const {
    return opcode;
  }

  virtual ResultType getResultType() const override {
    return resultType;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(children[0]->copy(), children[1]->copy(), opcode, resultType);
  }

  static std::unique_ptr<BinOp> create(
    std::unique_ptr<Expr> lhs,
    std::unique_ptr<Expr> rhs,
    Opcode opcode,
    ResultType resultType
  ) {
    std::vector<std::unique_ptr<Expr>> children;
    children.push_back(std::move(lhs));
    children.push_back(std::move(rhs));

    return std::unique_ptr<BinOp>(new BinOp(
      std::move(children),
      opcode,
      resultType
    ));
  }

protected:
  BinOp(
    std::vector<std::unique_ptr<Expr>> children,
    Opcode opcode,
    ResultType resultType
  ) : Expr(std::move(children)), opcode(opcode), resultType(resultType) {}

private:
  Opcode opcode;
  ResultType resultType;
};

}
