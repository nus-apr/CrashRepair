#include <crashrepairfix/ProgramMutator.h>

#include <crashrepairfix/ConstantFinder.h>
#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>
#include <crashrepairfix/Expr/ClangToExprConverter.h>
#include <crashrepairfix/Expr/ExprGenerator.h>
#include <crashrepairfix/Expr/Mutation/Mutations.h>

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
  spdlog::info("using fix constraint: {}", location.getConstraint()->toString());

  // FIXME top-level statements should be mutable!
  // if (!location.isMutable()) {
  //   spdlog::warn("ignoring unsupported statement [kind: {}]: {}", location.getStmtClassName(), location.getSource());
  //   return;
  // }

  if (linter.validate(location).has_value()) {
    spdlog::error(
      "skipping illegal fix location [{}] with constraint: {}",
      location.getLocation().toString(),
      location.getConstraint()->toString()
    );
    return;
  }

  if (location.isExprStmt()) {
    mutateExprStmt(location);
  } else {
    assert (!location.getConstraint()->refersToResult());
  }

  if (location.isConditionalStmt()) {
    mutateConditionalStmt(location);
  } else {
    mutateNonConditionalStmt(location);
  }
}

void ProgramMutator::mutateExprStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating expr statement [{}]: {}", location.getStmtClassName(), location.getSource());
  auto &context = location.getContext();

  auto *stmt = location.getStmt();
  auto originalSource = crashrepairfix::getSource(stmt, location.getSourceManager());
  auto sourceRange = crashrepairfix::getRangeWithTokenEnd(stmt, context);

  auto convertedExpr = ClangToExprConverter(context).convert(stmt);
  if (convertedExpr == nullptr) {
    spdlog::warn("ignoring expr statement [unable to lift to expression language]: {}", location.getSource());
    return;
  }
  spdlog::info("lifted statement to expr: {}", convertedExpr->toString());

  auto generator = ExprGenerator(
    convertedExpr.get(),
    location.getConstraint(),
    location.getStates()
  );
  // TODO add --max-expr-patches and --max-expr-edits options
  std::vector<std::unique_ptr<Expr>> mutations = generator.generate(50);
  spdlog::info("generated {} mutants", mutations.size());

  for (auto &replacementExpr : mutations) {
    auto replacementSource = replacementExpr->toSource();
    auto replacement = Replacement::replace(replacementSource, sourceRange, context);
    create(Operator::ExpressionMutation, location, {replacement});
  }
}

void ProgramMutator::mutateConditionalStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating conditional statement [{}]: {}", location.getStmtClassName(), location.getSource());
  strengthenBranchCondition(location);

  // in some cases, we want to weaken an existing branch condition that's used for error checking (see #99)
  weakenBranchCondition(location);
}

void ProgramMutator::mutateNonConditionalStmt(AstLinkedFixLocation &location) {
  spdlog::info("mutating non-conditional statement [{}]: {}", location.getStmtClassName(), location.getSource());

  if (location.isTopLevelStmt()) {
    prependConditionalControlFlow(location);
    guardStatement(location);
  }
}

void ProgramMutator::weakenBranchCondition(AstLinkedFixLocation &location) {
  spdlog::info("weakening branch condition in statement: {}", location.getSource());
  auto *condition = location.getBranchConditionExpression();
  auto &sourceManager = location.getSourceManager();
  auto constraintSource = location.getConstraint()->toSource();

  // #69: existing branch condition may be empty
  if (!condition) {
    return;
  }

  auto originalSource = crashrepairfix::getSource(condition, sourceManager);
  auto sourceRange = crashrepairfix::getRangeWithTokenEnd(condition, location.getContext());
  auto mutatedSource = fmt::format(
    "(!({})) || ({})",
    constraintSource,
    originalSource
  );
  auto replacement = Replacement::replace(mutatedSource, sourceRange, location.getContext());
  create(Operator::WeakenBranchCondition, location, {replacement});
}

void ProgramMutator::strengthenBranchCondition(AstLinkedFixLocation &location) {
  spdlog::info("strengthening branch condition in statement: {}", location.getSource());
  auto *stmt = location.getStmt();
  auto *condition = location.getBranchConditionExpression();
  auto &sourceManager = location.getSourceManager();
  auto constraintSource = location.getConstraint()->toSource();

  // #69: existing branch condition may be empty
  if (!condition) {
    if (auto *forStmt = clang::dyn_cast<clang::ForStmt>(stmt)) {
      auto sourceRange = clang::SourceRange(
        forStmt->getLParenLoc().getLocWithOffset(1),
        forStmt->getRParenLoc().getLocWithOffset(-1)
      );

      std::string initSource = "";
      if (auto initStmt = forStmt->getInit()) {
        initSource = crashrepairfix::getSource(initStmt, sourceManager);
        if (initSource.back() == ';') {
          initSource.pop_back();
        }
      }

      std::string incSource = "";
      if (auto incStmt = forStmt->getInc()) {
        incSource = crashrepairfix::getSource(incStmt, sourceManager);
      }

      auto mutatedSource = fmt::format(
        "{}; {}; {}",
        initSource,
        constraintSource,
        incSource
      );
      auto replacement = Replacement::replace(mutatedSource, sourceRange, location.getContext());
      create(Operator::StrengthenBranchCondition, location, {replacement});
    } else {
      spdlog::error("unable to handle empty branch condition in statement kind: {}", stmt->getStmtClassName());
    }
  } else {
    auto originalSource = crashrepairfix::getSource(condition, sourceManager);
    auto sourceRange = crashrepairfix::getRangeWithTokenEnd(condition, location.getContext());

    // add the constraint to the left of a short-circuited evaluation (see #99)
    auto mutatedSource = fmt::format(
      "({}) && ({})",
      constraintSource,
      originalSource
    );
    auto replacement = Replacement::replace(mutatedSource, sourceRange, location.getContext());
    create(Operator::StrengthenBranchCondition, location, {replacement});

    // add the constraint to the right of a short-circuited evaluation (see #99)
    mutatedSource = fmt::format(
      "({}) && ({})",
      originalSource,
      constraintSource
    );
    replacement = Replacement::replace(mutatedSource, sourceRange, location.getContext());
    create(Operator::StrengthenBranchCondition, location, {replacement});
  }
}

void ProgramMutator::prependConditionalControlFlow(AstLinkedFixLocation &location) {
  bool isInsideLoop = location.isInsideLoop();

  addConditionalExit(location);

  if (location.isInsideFunction()) {
    addConditionalReturn(location);
  }
  if (isInsideLoop || location.isInsideSwitch()) {
    addConditionalBreak(location);
  }
  if (isInsideLoop) {
    addConditionalContinue(location);
  }
}

void ProgramMutator::addConditional(AstLinkedFixLocation &location, std::string const &bodySource) {
  auto cfcSource = location.getConstraint()->toSource();
  auto insert = fmt::format("if (!({})) {{ {} }} ", cfcSource, bodySource);
  auto replacement = Replacement::prepend(insert, location);
  create(Operator::InsertConditionalControlFlow, location, {replacement});
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

void ProgramMutator::addConditionalExit(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional exit before statement: {}", location.getSource());
  // FIXME implement sophisticated version of this operator (see #106)
  addConditional(location, "exit(1);");
  addConditional(location, "exit(0);");
}

void ProgramMutator::addConditionalNonVoidReturn(AstLinkedFixLocation &location) {
  spdlog::info("inserting conditional non-void return before statement: {}", location.getSource());

  auto &context = location.getContext();

  std::set<std::string> returnValues;

  auto restrictConstantsToFile = location.getFilename();
  auto parentFunction = location.getParentFunction();
  // auto translationUnit = location.getParentTranslationUnit();
  auto returnType = parentFunction->getReturnType();
  auto returnTypeInfo = returnType.getTypePtr();

  if (returnTypeInfo->isIntegerType()) {
    returnValues.insert("-1");
    returnValues.insert("0");
    returnValues.insert("1");

    // auto constants = ConstantFinder::findIntegers(context, translationUnit, restrictConstantsToFile);
    // for (auto &integer : constants) {
    //   // TODO ensure that constant fits within return type!
    //   returnValues.insert(convertAPIntToString(integer));
    // }
  }

  if (returnTypeInfo->isRealType()) {
    returnValues.insert("-1.0");
    returnValues.insert("0.0");
    returnValues.insert("1.0");

    // auto constants = ConstantFinder::findReals(context, translationUnit, restrictConstantsToFile);
    // for (auto &real : constants) {
    //   // TODO ensure that constant fits within return type!
    //   returnValues.insert(convertAPFloatToString(real));
    // }
  }

  if (returnTypeInfo->isPointerType()) {
    returnValues.insert("0");

    if (returnTypeInfo->getPointeeType().getTypePtr()->isCharType()) {
      returnValues.insert("\"\"");
    }
  }

  // find reaching in-scope local variables with the same type
  for (auto varDecl : findReachingVars(location.getStmt(), const_cast<clang::ASTContext&>(context))) {
    if (varDecl->getType().getTypePtr() == returnTypeInfo) {
      returnValues.insert(varDecl->getNameAsString());
    }
  }

  for (auto &returnValue : returnValues) {
    auto snippet = fmt::format("return {};", returnValue);
    addConditional(location, snippet);
  }
}

void ProgramMutator::guardStatement(AstLinkedFixLocation &location) {
  auto stmt = location.getStmt();
  auto &context = location.getContext();
  auto source = location.getSource();
  auto sourceRange = crashrepairfix::getRangeWithTokenEnd(stmt, context);

  // get the trailing semi-colon
  auto semiLocation = findSemiAfterLocation(sourceRange.getEnd(), const_cast<clang::ASTContext&>(context));
  if (semiLocation.isValid()) {
    spdlog::debug("including semi-colon inside wrapped location");
    sourceRange = clang::SourceRange(sourceRange.getBegin(), semiLocation.getLocWithOffset(1));
    source = fmt::format("{};", source);
  }

  spdlog::info("wrapping guard around statement: {}", source);

  // for now, don't guard statements that contain a declaration
  // we can make this a little less strict by allowing a closing bracket to be placed at either:
  // - the end of the parent block
  // - the earliest possible point in the block that does not cause a compiler error
  if (containsVarDecl(stmt, context)) {
    spdlog::warn("skipping wrap guard statement [contains decl]: {}", source);
    return;
  }

  auto cfcSource = location.getConstraint()->toSource();
  auto mutatedSource = fmt::format("if ({}) {{ {} }}", cfcSource, source);
  auto replacement = Replacement::replace(mutatedSource, sourceRange, context);
  create(Operator::GuardStatement, location, {replacement});
}

void ProgramMutator::create(
  Operator op,
  AstLinkedFixLocation &location,
  std::vector<Replacement> const &replacements
) {
  size_t mutantId = mutations.size();
  std::string diff = diffGenerator.diff(replacements);
  mutations.emplace_back(mutantId, op, location.getLocation(), std::move(replacements), diff);
}

void ProgramMutator::save() {
  auto filename = saveToFilename;

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
