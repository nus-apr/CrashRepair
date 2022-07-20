#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

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

  static bool isArithmeticOpcode(Opcode const &opcode) {
    switch (opcode) {
      case Opcode::ADD:
      case Opcode::SUBTRACT:
      case Opcode::DIVIDE:
      case Opcode::MULTIPLY:
        return true;
      default:
        return false;
    }
  }

  static bool isLogicalOpcode(Opcode const &opcode) {
    switch (opcode) {
      case Opcode::AND:
      case Opcode::OR:
        return true;
      default:
        return false;
    }
  }

  static bool isRelationalOpcode(Opcode const &opcode) {
    switch (opcode) {
      case Opcode::LT:
      case Opcode::LTE:
      case Opcode::GT:
      case Opcode::GTE:
      case Opcode::EQ:
      case Opcode::NEQ:
        return true;
      default:
        return false;
    }
  }

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
    Opcode opcode
  ) {
    auto resultType = ResultType::Int;
    if (isArithmeticOpcode(opcode) && (lhs->getResultType() == ResultType::Float || rhs->getResultType() == ResultType::Float)) {
      resultType = ResultType::Float;
    }
    return create(std::move(lhs), std::move(rhs), opcode, resultType);
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

  static Opcode opcodeFromString(std::string const &string) {
    if (string == "<") {
      return Opcode::LT;
    } else if (string == "<=") {
      return Opcode::LTE;
    } else if (string == ">") {
      return Opcode::GT;
    } else if (string == ">=") {
      return Opcode::GTE;
    } else if (string == "==") {
      return Opcode::EQ;
    } else if (string == "!=") {
      return Opcode::NEQ;
    } else if (string == "&&") {
      return Opcode::AND;
    } else if (string == "||") {
      return Opcode::OR;
    } else if (string == "/") {
      return Opcode::DIVIDE;
    } else if (string == "-") {
      return Opcode::SUBTRACT;
    } else if (string == "+") {
      return Opcode::ADD;
    } else if (string == "*") {
      return Opcode::MULTIPLY;
    } else {
      spdlog::error("unrecognized binary opcode: {}", string);
      abort();
    }
  }

  static std::string opcodeToString(Opcode const &opcode) {
    switch (opcode) {
      case Opcode::LT:
        return "<";
      case Opcode::LTE:
        return "<=";
      case Opcode::GT:
        return ">";
      case Opcode::GTE:
        return ">=";
      case Opcode::EQ:
        return "==";
      case Opcode::NEQ:
        return "!=";
      case Opcode::AND:
        return "&&";
      case Opcode::OR:
        return "||";
      case Opcode::DIVIDE:
        return "/";
      case Opcode::SUBTRACT:
        return "-";
      case Opcode::ADD:
        return "+";
      case Opcode::MULTIPLY:
        return "*";
    }
  }

  std::string getOpcodeString() const {
    return opcodeToString(opcode);
  }

  Expr * getLhs() {
    return children[0].get();
  }
  Expr const * getLhs() const {
    return children[0].get();
  }
  Expr * getRhs() {
    return children[1].get();
  }
  Expr const * getRhs() const {
    return children[1].get();
  }

  virtual std::string toSource() const override {
    return fmt::format(
      "({} {} {})",
      getLhs()->toSource(),
      getOpcodeString(),
      getRhs()->toSource()
    );
  }

  virtual std::string toString() const override {
    return fmt::format(
      "({} {} {})",
      getLhs()->toString(),
      getOpcodeString(),
      getRhs()->toString()
    );
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
