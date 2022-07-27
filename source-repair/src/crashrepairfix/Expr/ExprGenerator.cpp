#include <crashrepairfix/Expr/ExprGenerator.h>

namespace crashrepairfix {

std::vector<std::unique_ptr<Expr>> ExprGenerator::generate(size_t limit) const {
  auto mutations = ExprMutations::generate(expr, maxEdits);
  mutations.add(std::make_unique<ReplaceVarRefMutator>(states));

  auto resultReference = constraint->getResultReference();
  assert (resultReference != nullptr);

  // NOTE store this as a field?
  z3::context z3c;
  auto z3Converter = ExprToZ3Converter(z3c);
  auto z3Constraint = z3Converter.convert(constraint);
  auto z3ResultVar = z3Converter.convert(resultReference);

  std::function<bool(Expr const *)> satisfies = [&](Expr const *expr) -> bool {
    // NOTE we check each observation individually (rather than creating a single query)
    // NOTE store solver as a field?
    spdlog::debug("checking expression: {}", expr->toSource());
    for (auto const &values : states.getValues()) {
      z3::solver solver(z3c);
      solver.add(z3Constraint);
      solver.add(values->toZ3(z3c));
      solver.add(z3ResultVar == z3Converter.convert(expr));
      switch (solver.check()) {
        case z3::sat:
          break;
        case z3::unsat:
          return false;
        case z3::unknown:
          llvm::errs() << "WARNING: unable to determine whether repair satisfies CFC\n";
          return false;
      }
    }
    return true;
  };

  return mutations.filter(satisfies, limit);
}

}
