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
  abort();
}

z3::expr ExprToZ3Converter::convert(UnaryOp const *expr) {
  abort();
}

z3::expr ExprToZ3Converter::convert(IntConst const *expr) {
  return z3c.int_val(static_cast<__int64_t>(expr->getValue()));
}

z3::expr ExprToZ3Converter::convert(FloatConst const *expr) {
  return z3c.fpa_val(expr->getValue());
}

z3::expr ExprToZ3Converter::convert(NullConst const *expr) {
  abort();
}

z3::expr ExprToZ3Converter::convert(Result const *expr) {
  abort();
}

z3::expr ExprToZ3Converter::convert(Var const *expr) {
  abort();
}

}
