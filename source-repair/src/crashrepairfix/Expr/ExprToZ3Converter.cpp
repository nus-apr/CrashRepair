#include <crashrepairfix/Expr/ExprToZ3Converter.h>

#include <spdlog/spdlog.h>

namespace crashrepairfix {

z3::expr ExprToZ3Converter::convert(Expr const *expr) {
  auto kind = expr->getExprKind();
  switch (kind) {
    case Expr::Kind::BinOp:
      return convert(static_cast<BinOp const *>(expr));
    case Expr::Kind::UnaryOp:
      return convert(static_cast<UnaryOp const *>(expr));
    case Expr::Kind::FloatConst:
      return convert(static_cast<FloatConst const *>(expr));
    case Expr::Kind::IntConst:
      return convert(static_cast<IntConst const *>(expr));
    case Expr::Kind::NullConst:
      return convert(static_cast<NullConst const *>(expr));
    case Expr::Kind::Var:
      return convert(static_cast<Var const *>(expr));
    case Expr::Kind::Result:
      return convert(static_cast<Result const *>(expr));
    default:
      spdlog::error(
        "unable to convert expression to Z3 [unknown kind: {}]: {}",
        Expr::exprKindToString(kind),
        expr->toString()
      );
      abort();
  }
}

z3::expr ExprToZ3Converter::convert(BinOp const *expr) {
  auto lhsZ3 = convert(expr->getLhs());
  auto rhsZ3 = convert(expr->getRhs());
  switch (expr->getOpcode()) {
    case BinOp::Opcode::ADD:
      return lhsZ3 + rhsZ3;
    case BinOp::Opcode::SUBTRACT:
      return lhsZ3 - rhsZ3;
    case BinOp::Opcode::DIVIDE:
      return lhsZ3 / rhsZ3;
    case BinOp::Opcode::MULTIPLY:
      return lhsZ3 * rhsZ3;

    // FIXME without first-class treatment of booleans, this will fail
    case BinOp::Opcode::AND:
      return lhsZ3 && rhsZ3;
    case BinOp::Opcode::OR:
      return lhsZ3 || rhsZ3;

    case BinOp::Opcode::LT:
      return lhsZ3 < rhsZ3;
    case BinOp::Opcode::LTE:
      return lhsZ3 <= rhsZ3;
    case BinOp::Opcode::GT:
      return lhsZ3 > rhsZ3;
    case BinOp::Opcode::GTE:
      return lhsZ3 >= rhsZ3;
    case BinOp::Opcode::EQ:
      return lhsZ3 == rhsZ3;
    case BinOp::Opcode::NEQ:
      return lhsZ3 != rhsZ3;

    case BinOp::Opcode::LEFT_SHIFT:
      return z3::bv2int(z3::shl(z3::int2bv(64, lhsZ3), z3::int2bv(64, rhsZ3)), true);
    case BinOp::Opcode::RIGHT_SHIFT:
      return z3::bv2int(z3::ashr(z3::int2bv(64, lhsZ3), z3::int2bv(64, rhsZ3)), true);
  }
  assert (false);
}

z3::expr ExprToZ3Converter::convert(UnaryOp const *expr) {
  auto operandZ3 = convert(expr->getOperand());
  switch (expr->getOpcode()) {
    case UnaryOp::Opcode::NOT:
      return !operandZ3;
  }
  assert (false);
}

z3::expr ExprToZ3Converter::convert(IntConst const *expr) {
  return z3c.int_val(expr->getValue());
}

z3::expr ExprToZ3Converter::convert(FloatConst const *expr) {
  return z3c.fpa_val(expr->getValue());
}

z3::expr ExprToZ3Converter::convert(NullConst const *expr) {
  return z3c.int_val(0);
}

z3::expr ExprToZ3Converter::convert(Result const *expr) {
  static std::string const name = "RESULT";
  switch (expr->getResultType()) {
    case ResultType::Float:
      return z3c.real_const(name.c_str());
    case ResultType::Int:
    case ResultType::Pointer:
      return z3c.int_const(name.c_str());
  }
  assert (false);
}

z3::expr ExprToZ3Converter::convert(Var const *expr) {
  std::string const &name = expr->getName();
  switch (expr->getResultType()) {
    case ResultType::Float:
      return z3c.real_const(name.c_str());
    case ResultType::Int:
    case ResultType::Pointer:
      return z3c.int_const(name.c_str());
  }
  assert (false);
}

}
