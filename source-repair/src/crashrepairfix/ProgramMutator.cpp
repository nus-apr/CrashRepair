#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

using json = nlohmann::json;

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

  // NOTE this code is in here solely to test the Mutation class functionality
  auto cfcSource = "5 < 10";  // TODO Expr.toSource();
  auto insert = fmt::format("if (!({})) {{ return; }} ", cfcSource);
  spdlog::info("inserting code before statement: {}", insert);

  auto replacement = Replacement::prepend(insert, location);
  create(location, {replacement});
}

void ProgramMutator::addConditionalNonVoidReturn(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional non-void return before statement: {}", location.getSource());
}

void ProgramMutator::guardStatement(AstLinkedFixLocation &location) {
  spdlog::info("wrapping guard around statement: {}", location.getSource());
}

void ProgramMutator::create(AstLinkedFixLocation &location, std::vector<Replacement> const &replacements) {
  size_t mutantId = mutations.size();
  std::string diff = diffGenerator.diff(replacements);
  mutations.emplace_back(mutantId, location.getLocation(), std::move(replacements), diff);
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
