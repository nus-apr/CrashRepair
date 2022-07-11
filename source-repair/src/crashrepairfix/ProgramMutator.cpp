#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>

#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace crashrepairfix {

void ProgramMutator::mutate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto *stmt = StmtFinder::find(context, location.getLocation());
    if (stmt == nullptr) {
      continue;
    }

    spdlog::info("found matching statement: {}", getSource(stmt, context));
    mutate(stmt, context);
  }
}

void ProgramMutator::mutate(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("mutating statement [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));

  if (   clang::isa<clang::SwitchCase>(stmt)
      || clang::isa<clang::SwitchStmt>(stmt)
      || clang::isa<clang::CompoundStmt>(stmt)
  ) {
    spdlog::warn("ignoring unsupported statement kind [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));
    return;
  }

  bool isConditionalStmt = (
       clang::isa<clang::IfStmt>(stmt)
    || clang::isa<clang::ForStmt>(stmt)
    || clang::isa<clang::WhileStmt>(stmt)
  );

  if (isConditionalStmt) {
    mutateConditionalStmt(stmt, context);
  } else {
    mutateNonConditionalStmt(stmt, context);
  }
}

void ProgramMutator::mutateConditionalStmt(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("mutating conditional statement [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));
}

void ProgramMutator::mutateNonConditionalStmt(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("mutating non-conditional statement [{}]: {}", stmt->getStmtClassName(), getSource(stmt, context));

  // TODO ensure that this is a top-level stmt

  prependConditionalControlFlow(stmt, context);
  guardStatement(stmt, context);

  // TODO is this an assignment?
}

void ProgramMutator::prependConditionalControlFlow(clang::Stmt *stmt, clang::ASTContext &context) {
  addConditionalReturn(stmt, context);
  if (isInsideLoop(stmt, context)) {
    addConditionalBreak(stmt, context);
    addConditionalContinue(stmt, context);
  }
}

void ProgramMutator::addConditionalBreak(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("inserting conditional break before statement: {}", getSource(stmt, context));
}

void ProgramMutator::addConditionalContinue(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("inserting conditional continue before statement: {}", getSource(stmt, context));
}

void ProgramMutator::addConditionalReturn(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("inserting conditional return before statement: {}", getSource(stmt, context));
}

void ProgramMutator::guardStatement(clang::Stmt *stmt, clang::ASTContext &context) {
  spdlog::info("wrapping guard around statement: {}", getSource(stmt, context));

  // NOTE this is 
}

void ProgramMutator::save() {
  // FIXME allow this to be customized
  std::string filename = "mutations.json";

  spdlog::info("writing {} mutations to disk: {}", mutations.size(), filename);
  json j = json::array();
  for (auto &mutation : mutations) {
    j.push_back(mutation.toJson());
  }

  std::ofstream o(filename);
  o << std::setw(2) << j << std::endl;
  spdlog::info("wrote mutations to disk");
}

}
