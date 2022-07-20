#include <crashrepairfix/ProgramMutator.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>
#include <crashrepairfix/Expr/ClangToExprConverter.h>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

using json = nlohmann::json;

namespace crashrepairfix {

void ProgramMutator::mutate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto stmtLocation = location->getLocation();
    auto *stmt = StmtFinder::find(context, stmtLocation);
    if (stmt == nullptr) {
      spdlog::warn("unable to find statement at location: {}", stmtLocation.toString());
      continue;
    }

    AstLinkedFixLocation linkedLocation = AstLinkedFixLocation::create(*location, stmt, context);
    spdlog::info("found matching statement: {}", linkedLocation.getSource());
    mutate(linkedLocation);
  }
}

void ProgramMutator::mutate(AstLinkedFixLocation &location) {
  spdlog::info("mutating statement [{}]: {}", location.getStmtClassName(), location.getSource());
  spdlog::info("using fix constraint: {}", location.getConstraint()->toSource());

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

  // FIXME debugging
  // let's try to mutate the condition
  auto *condition = location.getBranchConditionExpression();
  auto converter = ClangToExprConverter(location.getContext());
  auto conditionExpr = converter.convert(condition);
  spdlog::info("converted condition to expression: {}", conditionExpr->toString());

  strengthenBranchCondition(location);
}

void ProgramMutator::mutateNonConditionalStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating non-conditional statement [{}]: {}", location.getStmtClassName(), location.getSource());

  // TODO ensure that this is a top-level stmt

  prependConditionalControlFlow(location);
  guardStatement(location);

  // TODO is this an assignment?
}

void ProgramMutator::strengthenBranchCondition(AstLinkedFixLocation &location) {
  spdlog::info("strengthening branch condition in statement: {}", location.getSource());
  auto *condition = location.getBranchConditionExpression();
  auto originalSource = crashrepairfix::getSource(condition, location.getSourceManager());
  auto sourceRange = crashrepairfix::getRangeWithTokenEnd(condition, location.getContext());
  auto mutatedSource = fmt::format(
    "({}) && {}",
    originalSource,
    location.getConstraint()->toSource()
  );
  auto replacement = Replacement::replace(mutatedSource, sourceRange, location.getContext());
  create(location, {replacement});
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

void ProgramMutator::addConditional(AstLinkedFixLocation &location, std::string const &bodySource) {
  auto cfcSource = location.getConstraint()->toSource();
  auto insert = fmt::format("if (!({})) {{ {{}} }} ", cfcSource, bodySource);
  auto replacement = Replacement::prepend(insert, location);
  create(location, {replacement});
}

void ProgramMutator::addConditionalBreak(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional break before statement: {}", location.getSource());
  addConditional(location, "break;");
}

void ProgramMutator::addConditionalContinue(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional continue before statement: {}", location.getSource());
  addConditional(location, "continue;");
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
  addConditional(location, "return;");
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
