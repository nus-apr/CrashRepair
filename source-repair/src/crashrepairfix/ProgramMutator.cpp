#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>

#include <spdlog/spdlog.h>

using json = nlohmann::json;

// TODO bundle clang::Stmt, clang::ASTContext, and FixLocation into a single data structure
// - can also add clang::FunctionDecl for parent function

namespace crashrepairfix {

void ProgramMutator::mutate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto *stmt = StmtFinder::find(context, location.getLocation());
    if (stmt == nullptr) {
      continue;
    }

    AstLinkedFixLocation linkedLocation = AstLinkedFixLocation::create(location, stmt, context);
    spdlog::info("found matching statement: {}", linkedLocation.getSource());
    mutate(linkedLocation);
  }
}

void ProgramMutator::mutate(AstLinkedFixLocation &location) {
  spdlog::info("mutating statement [{}]: {}", location.getStmtClassName(), location.getSource());

  auto *stmt = location.getStmt();

  if (   clang::isa<clang::SwitchCase>(stmt)
      || clang::isa<clang::SwitchStmt>(stmt)
      || clang::isa<clang::CompoundStmt>(stmt)
  ) {
    spdlog::warn("ignoring unsupported statement [kind: {}]: {}", location.getStmtClassName(), location.getSource());
    return;
  }

  if (location.isConditionalStmt()) {
    mutateConditionalStmt(location);
  } else {
    mutateNonConditionalStmt(location);
  }
}

void ProgramMutator::mutateConditionalStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating conditional statement [{}]: {}", location.getStmtClassName(), location.getSource());
}

void ProgramMutator::mutateNonConditionalStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating non-conditional statement [{}]: {}", location.getStmtClassName(), location.getSource());

  // TODO ensure that this is a top-level stmt

  prependConditionalControlFlow(location);
  guardStatement(location);

  // TODO is this an assignment?
}

void ProgramMutator::prependConditionalControlFlow(AstLinkedFixLocation &location) {
  if (location.isInsideFunction()) {
    addConditionalReturn(location);
  }
  if (location.isInsideLoop()) {
    addConditionalBreak(location);
    addConditionalContinue(location);
  }
}

void ProgramMutator::addConditionalBreak(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional break before statement: {}", location.getSource());
}

void ProgramMutator::addConditionalContinue(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional continue before statement: {}", location.getSource());
}

void ProgramMutator::addConditionalReturn(AstLinkedFixLocation &location) {
  if (location.isInsideVoidFunction()) {
    addConditionalVoidReturn(location);
  } else {
    addConditionalNonVoidReturn(location);
  }
}

void ProgramMutator::addConditionalVoidReturn(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional void return before statement: {}", location.getSource());
}

void ProgramMutator::addConditionalNonVoidReturn(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional non-void return before statement: {}", location.getSource());
}

void ProgramMutator::guardStatement(AstLinkedFixLocation &location) {
  spdlog::info("wrapping guard around statement: {}", location.getSource());
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
