#include <crashrepairfix/FixLocationLinter.h>

#include <crashrepairfix/StmtFinder.h>
#include <crashrepairfix/Utils.h>
#include <crashrepairfix/Expr/ClangToExprConverter.h>
#include <crashrepairfix/Expr/ExprGenerator.h>
#include <crashrepairfix/Expr/Mutation/Mutations.h>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

using json = nlohmann::json;

namespace crashrepairfix {

std::string LinterError::typeToString() const {
  switch (type) {
    case LinterErrorType::ResultAtTopLevelConstraint:
      return "result-at-top-level-constraint";
    case LinterErrorType::NonResultAtNonTopLevelConstraint:
      return "non-result-at-non-top-level-constraint";
    case LinterErrorType::UnableToLocateStatement:
      return "unable-to-locate-statement";
   case LinterErrorType::ResultAtNonExprStatement:
      return "result-at-non-expr-statement";
   case LinterErrorType::ResultTypeDoesNotMatchExprType:
      return "result-type-does-not-match-expr-type";
    default:
      spdlog::error("cannot convert LinterErrorType to string: unrecognized kind");
      abort();
  }
}

std::string LinterError::message() const {
  std::string message;
  switch (type) {
    case LinterErrorType::ResultAtTopLevelConstraint:
      message = fmt::format("@result constraint at top-level statement [{}]", location->getConstraint()->toString());
      break;
    case LinterErrorType::NonResultAtNonTopLevelConstraint:
      message = fmt::format("non-@result constraint at non-top-level statement [{}]", location->getConstraint()->toString());
      break;
    case LinterErrorType::UnableToLocateStatement:
      message = "unable to find statement";
      break;
    case LinterErrorType::ResultAtNonExprStatement:
      message = "@result constraint given at a non-expression statement";
      break;
    case LinterErrorType::ResultTypeDoesNotMatchExprType:
      message = "@result type does not match expression type";
      break;
    default:
      spdlog::error("unable to transform linter error into message");
      abort();
  }
  return fmt::format("bad fix location [{}]: {}", location->getLocation().toString(), message);
}

nlohmann::json LinterError::toJson() const {
  return {
    {"location", location->getLocation().toString()},
    {"constraint", location->getConstraint()->toString()},
    {"type", typeToString()},
    {"description", message()}
  };
}

void FixLocationLinter::run(clang::ASTContext &context) {
  if (shouldRepair) {
    repair(context);
  } else {
    validate(context);
  }
}

std::unique_ptr<FixLocation> FixLocationLinter::repair(AstLinkedFixLocation const &location) {
  clang::ASTContext &context = const_cast<clang::ASTContext&>(location.getContext());

  // repair is only applied to non-constraint fix locations
  if (location.getConstraint()->refersToResult()) {
    return {};
  }

  auto originalStmt = location.getStmt();
  auto topLevelStmt = findTopLevelStmt(originalStmt, context);
  if (topLevelStmt == originalStmt) {
    return {};
  }

  // create a new fix location
  clang::SourceLocation stmtClangRawLocation = topLevelStmt->getBeginLoc();
  if (auto binOp = clang::dyn_cast<clang::BinaryOperator>(topLevelStmt)) {
    stmtClangRawLocation = binOp->getOperatorLoc();
  }
  auto stmtClangLocation = context.getFullLoc(stmtClangRawLocation);

  auto lineNumber = stmtClangLocation.getLineNumber();
  auto columnNumber = stmtClangLocation.getColumnNumber();
  // see #54
  auto filename = std::filesystem::path(location.getLocation().file).lexically_normal().string();
  auto sourceLocation = SourceLocation(
    filename,
    lineNumber,
    columnNumber
  );

  return std::make_unique<FixLocation>(
    sourceLocation,
    location.getConstraint()->copy(),
    ProgramStates(location.getStates()),
    location.getDistance()
  );
}

std::optional<LinterError> FixLocationLinter::validate(AstLinkedFixLocation const &location) {
  auto constraint = location.getConstraint();
  auto isResultExpr = constraint->refersToResult();
  if (isResultExpr && location.isTopLevelStmt()) {
    return LinterError::ResultAtTopLevelConstraint(&location.getFixLocation());
  }
  if (!isResultExpr && !location.isTopLevelStmt()) {
    return LinterError::NonResultAtNonTopLevelConstraint(&location.getFixLocation());
  }

  auto *clangExpr = clang::dyn_cast<clang::Expr>(location.getStmt());
  if (isResultExpr) {
    if (clangExpr == nullptr) {
      return LinterError::ResultAtNonExprStatement(&location.getFixLocation());
    }

    // FIXME boolean expressions are reported as ints
    spdlog::debug(
      "checking result type [{}] of statement: {} [{}]",
      location.getConstraint()->getResultTypeString(),
      location.getSource(),
      clangExpr->getType().getAsString()
    );
    auto clangExprType = clangExpr->getType().getTypePtr();
    auto resultType = constraint->getResultReference()->getResultType();
    if (resultType == ResultType::Int && !clangExprType->isIntegralType(location.getContext())) {
      return LinterError::ResultTypeDoesNotMatchExprType(&location.getFixLocation());
    } else if (stmtIsBoolExpr(location.getStmt())) {
      return LinterError::ResultTypeDoesNotMatchExprType(&location.getFixLocation());
    } else if (resultType == ResultType::Int && clangExprType->isBooleanType()) {// FIXME!
      return LinterError::ResultTypeDoesNotMatchExprType(&location.getFixLocation());
    } else if (resultType == ResultType::Float && !clangExprType->isFloatingType()) {
      return LinterError::ResultTypeDoesNotMatchExprType(&location.getFixLocation());
    } else if (resultType == ResultType::Pointer && !clangExprType->isPointerType()) {
      return LinterError::ResultTypeDoesNotMatchExprType(&location.getFixLocation());
    }
  }

  // see #54
  if (!location.getLocation().filenameIsNormal()) {
    return LinterError::NonNormalFilename(&location.getFixLocation());
  }

  return {};
}

void FixLocationLinter::repair(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto stmtLocation = location->getLocation();
    auto *stmt = StmtFinder::find(context, stmtLocation);

    // see #53
    if (!stmtLocation.filenameIsNormal()) {
      stmtLocation = stmtLocation.normalize();
      location->setLocation(stmtLocation);
      spdlog::info("normalized fix location: {}", stmtLocation.toString());
      stmt = StmtFinder::find(context, stmtLocation);
    }

    if (stmt == nullptr) {
      continue;
    }

    AstLinkedFixLocation linkedLocation = AstLinkedFixLocation::create(*location, stmt, context);
    auto fixedLocation = repair(linkedLocation);
    if (fixedLocation) {
      spdlog::info(
        "applying repair to fix location [{}] -> [{}]",
        location->getLocation().toString(),
        fixedLocation->getLocation().toString()
      );
      location->setLocation(fixedLocation->getLocation());
    }
  }
}

void FixLocationLinter::validate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto stmtLocation = location->getLocation();
    auto *stmt = StmtFinder::find(context, stmtLocation);
    if (stmt == nullptr) {
      auto error = LinterError::UnableToLocateStatement(location.get());
      spdlog::error(error.message());
      errors.push_back(error);
      continue;
    }

    AstLinkedFixLocation linkedLocation = AstLinkedFixLocation::create(*location, stmt, context);
    auto maybeError = validate(linkedLocation);
    if (maybeError) {
      spdlog::error(maybeError->message());
      errors.push_back(*maybeError);
    }
  }
}

bool FixLocationLinter::hasFoundErrors() const {
  return !errors.empty();
}

void FixLocationLinter::save(std::string const &saveToFilename) const {
  spdlog::info("writing linter report to disk");
  json j = json::array();
  for (auto &error : errors) {
    j.push_back(error.toJson());
  }
  j = {{"errors", j}};

  std::ofstream o(saveToFilename);
  o << std::setw(2) << j << std::endl;
  spdlog::info("wrote linter report to disk");
}

}
