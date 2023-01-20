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
    case LinterErrorType::NonResultAtNonTopLevelConstraint:
      message = fmt::format("illegal constraint at given location [{}]", location->getConstraint()->toString());
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

  return {};
}

void FixLocationLinter::validate(clang::ASTContext &context) {
  for (auto &location : fixLocalization) {
    auto stmtLocation = location->getLocation();
    auto *stmt = StmtFinder::find(context, stmtLocation);
    if (stmt == nullptr) {
      auto error = LinterError::UnableToLocateStatement(location.get());
      spdlog::error(error.message());
      errors.push_back(error);
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
