#pragma once

#include "Expr.h"

namespace crashrepairfix {

class UnaryOp : public Expr {
public:
  enum class Opcode {
    NOT,
  };

  Expr::Kind getExprKind() const override {
    return Expr::Kind::UnaryOp;
  }

  Opcode getOpcode() const {
    return opcode;
  }

  virtual ResultType getResultType() const override {
    return resultType;
  }

  virtual std::unique_ptr<Expr> copy() const override {
    return create(children[0]->copy(), opcode, resultType);
  }

  static std::unique_ptr<UnaryOp> create(
    std::unique_ptr<Expr> operand,
    Opcode opcode,
    ResultType resultType
  ) {
    std::vector<std::unique_ptr<Expr>> children;
    children.push_back(std::move(operand));

    return std::unique_ptr<UnaryOp>(new UnaryOp(
      std::move(children),
      opcode,
      resultType
    ));
  }

  static std::string opcodeToString(Opcode const &opcode) {
    switch (opcode) {
      case Opcode::NOT:
        return "!";
    }
  }

  std::string getOpcodeString() const {
    return opcodeToString(opcode);
  }

  Expr * getOperand() {
    return children[0].get();
  }
  Expr const * getOperand() const {
    return children[0].get();
  }

  virtual std::string toSource() const override {
    return fmt::format(
      "(! {})",
      getOpcodeString(),
      getOperand()->toSource()
    );
  }

  virtual std::string toString() const override {
    return fmt::format(
      "(! {})",
      getOpcodeString(),
      getOperand()->toString()
    );
  }

protected:
  UnaryOp(
    std::vector<std::unique_ptr<Expr>> children,
    Opcode opcode,
    ResultType resultType
  ) : Expr(std::move(children)), opcode(opcode), resultType(resultType) {}

private:
  Opcode opcode;
  ResultType resultType;
};

}
