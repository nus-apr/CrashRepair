#include <crashrepairfix/Expr/ExprGenerator.h>

namespace crashrepairfix {

std::vector<std::unique_ptr<Expr>> ExprGenerator::generate(size_t limit) const {
  auto mutations = ExprMutations::generate(expr, maxEdits);

  // NOTE store this as a field?
  z3::context z3c;
  auto z3Converter = ExprToZ3Converter(z3c);
  auto z3Constraint = z3Converter.convert(constraint);
  auto z3ResultVar = z3Converter.convert(expr->getResultReference());

  std::function<bool(Expr const *)> satisfies = [&](Expr const *expr) -> bool {
    // TODO check each observation individually (rather than creating a single query)
    // TODO store solver as a field
    for (auto &values : states.getValues()) {
      z3::solver solver(z3c);
      solver.add(z3Constraint);
      solver.add(values.toZ3(z3c));
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
