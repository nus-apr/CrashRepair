#include <crashrepairfix/Expr/ClangToExprConverter.h>

#include <spdlog/spdlog.h>

namespace crashrepairfix {

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::Stmt const *stmt) const {
  if (auto clangExpr = clang::dyn_cast<clang::Expr>(stmt)) {
    return convert(clangExpr);
  }

  spdlog::error("unable to convert clang::Stmt: must be a clang::Expr (actual: {})", stmt->getStmtClassName());
  return nullptr;
}

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::Expr const *clangExpr) const {
  clangExpr = clangExpr->IgnoreImplicit();

  if (auto integerLiteral = clang::dyn_cast<clang::IntegerLiteral>(clangExpr)) {
    return convert(integerLiteral);
  } else if (auto floatLiteral = clang::dyn_cast<clang::FloatingLiteral>(clangExpr)) {
    return convert(floatLiteral);
  } else if (auto binOp = clang::dyn_cast<clang::BinaryOperator>(clangExpr)) {
    return convert(binOp);
  } else if (auto declRefExpr = clang::dyn_cast<clang::DeclRefExpr>(clangExpr)) {
    return convert(declRefExpr);
  }

  spdlog::error("unable to convert clang expression: unsupported class [{}]: {}",
    clangExpr->getStmtClassName(),
    getSource(clangExpr)
  );
  return nullptr;
}

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::DeclRefExpr const *declRefExpr) const {
  auto *clangType = declRefExpr->getType().getTypePtrOrNull();
  auto typeName = declRefExpr->getType().getCanonicalType().getAsString();
  if (clangType == nullptr) {
    spdlog::error("failed to obtain type for DeclRefExpr: {}", getSource(declRefExpr));
    return nullptr;
  }

  ResultType resultType;
  if (clangType->isIntegralType(context)) {
    resultType = ResultType::Int;
  } else if (clangType->isRealType()) {
    resultType = ResultType::Float;
  } else if (clangType->isPointerType()) {
    resultType = ResultType::Pointer;
  } else {
    spdlog::error("unable to convert DeclRefExpr: unsupported type [{}]", typeName);
    return nullptr;
  }

  auto sourceAsName = getSource(declRefExpr);
  return Var::create(sourceAsName, resultType);
}

std::string ClangToExprConverter::getSource(clang::Stmt const *stmt) const {
  return crashrepairfix::getSource(stmt, sourceManager);
}

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::IntegerLiteral const *literal) const {
  double value = literal->getValue().bitsToDouble();
  return IntConst::create(long(value));
}

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::FloatingLiteral const *literal) const {
  double value = literal->getValue().convertToDouble();
  return FloatConst::create(value);
}

std::unique_ptr<Expr> ClangToExprConverter::convert(clang::BinaryOperator const *binOp) const {
  auto opcodeName = binOp->getOpcodeStr().str();
  auto maybeOpcode = BinOp::opcodeFromString(opcodeName);
  if (!maybeOpcode.has_value()) {
    spdlog::error("unable to obtain opcode from binary operator statement: {}", opcodeName);
    return nullptr;
  }

  auto lhs = convert(binOp->getLHS());
  auto rhs = convert(binOp->getRHS());
  if (lhs == nullptr || rhs == nullptr) {
    return nullptr;
  }

  return BinOp::create(
    std::move(lhs),
    std::move(rhs),
    maybeOpcode.value()
  );
}

}
