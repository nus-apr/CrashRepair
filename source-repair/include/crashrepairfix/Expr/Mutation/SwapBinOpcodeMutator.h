#pragma once

#include "Mutator.h"
#include "../BinOp.h"

namespace crashrepairfix {

class SwapBinOpcodeMutator : public ExprMutator {
public:
  SwapBinOpcodeMutator(){}
  ~SwapBinOpcodeMutator(){}

  std::string getName() const override {
    return "swap-binopcode";
  }

  void generate(Expr const *expr, std::vector<std::unique_ptr<ExprEdit>> &edits) override {
    if (expr->getExprKind() != Expr::Kind::BinOp) {
      return;
    }

    static constexpr BinOp::Opcode relationalOpcodes[] = {
      BinOp::Opcode::LT,
      BinOp::Opcode::LTE,
      BinOp::Opcode::GT,
      BinOp::Opcode::GTE,
      BinOp::Opcode::NEQ,
      BinOp::Opcode::EQ,
    };
    static constexpr BinOp::Opcode logicalOpcodes[] = {
      BinOp::Opcode::AND,
      BinOp::Opcode::OR,
    };
    static constexpr BinOp::Opcode arithmeticOpcodes[] = {
      BinOp::Opcode::SUBTRACT,
      BinOp::Opcode::ADD,
      BinOp::Opcode::DIVIDE,
      BinOp::Opcode::MULTIPLY,
    };

    auto const *binOp = static_cast<BinOp const *>(expr);
    auto oldOpcode = binOp->getOpcode();
    auto oldOpcodeString = BinOp::opcodeToString(oldOpcode);

    if (binOp->isLogicalOpcode(oldOpcode)) {
      spdlog::debug("mutating logical opcode: {}", oldOpcodeString);
      for (auto newOpcode : logicalOpcodes) {
        if (newOpcode != oldOpcode) {
          edits.emplace_back(std::make_unique<Edit>(newOpcode));
        }
      }
    } else if (binOp->isRelationalOpcode(oldOpcode)) {
      spdlog::debug("mutating relational opcode: {}", oldOpcodeString);
      for (auto newOpcode : relationalOpcodes) {
        if (newOpcode != oldOpcode) {
          edits.emplace_back(std::make_unique<Edit>(newOpcode));
        }
      }
    } else if (binOp->isArithmeticOpcode(oldOpcode)) {
      spdlog::debug("mutating arithemtic opcode: {}", oldOpcodeString);
      for (auto newOpcode : arithmeticOpcodes) {
        if (newOpcode != oldOpcode) {
          edits.emplace_back(std::make_unique<Edit>(newOpcode));
        }
      }
    }
  }

private:
  class Edit : public ExprEdit {
  public:
    void apply(Expr* expr) const override {
      static_cast<BinOp *>(expr)->changeOpcode(opcode);
    }

    Edit(BinOp::Opcode opcode) : opcode(opcode) {}
    ~Edit(){}

  private:
    BinOp::Opcode opcode;
  };
};

}
