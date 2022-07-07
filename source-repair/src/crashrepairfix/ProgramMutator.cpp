#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>

#include <spdlog/spdlog.h>

namespace crashrepairfix {

void ProgramMutator::mutate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto *stmt = StmtFinder::find(context, location.getLocation());
    if (stmt == nullptr) {
      continue;
    }

    spdlog::info("found matching statement: {}", getSource(stmt, context));
    // TODO mutate this statement
    // mutate(stmt, context);
  }
}

void ProgramMutator::mutate(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("mutating statement [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));
}

}
