#pragma once

#include <optional>
#include <string>

#include <clang/AST/ASTContext.h>

#include "AstLinkedFixLocation.h"
#include "FixLocalization.h"

namespace crashrepairfix {

enum class LinterErrorType {
  ResultAtTopLevelConstraint,
  NonResultAtNonTopLevelConstraint,
  UnableToLocateStatement,
  ResultAtNonExprStatement,
  ResultTypeDoesNotMatchExprType,
  NonNormalFilename
};

class LinterError {
public:
  LinterError(
    FixLocation const *location,
    LinterErrorType type
  ) :
    location(location),
    type(type)
  {}

  std::string typeToString() const;
  std::string message() const;
  nlohmann::json toJson() const;

  static LinterError ResultAtTopLevelConstraint(FixLocation const *location) {
    return LinterError(location, LinterErrorType::ResultAtTopLevelConstraint);
  }

  static LinterError NonResultAtNonTopLevelConstraint(FixLocation const *location) {
    return LinterError(location, LinterErrorType::NonResultAtNonTopLevelConstraint);
  }

  static LinterError UnableToLocateStatement(FixLocation const *location) {
    return LinterError(location, LinterErrorType::UnableToLocateStatement);
  }

  static LinterError ResultAtNonExprStatement(FixLocation const *location) {
    return LinterError(location, LinterErrorType::ResultAtNonExprStatement);
  }

  static LinterError ResultTypeDoesNotMatchExprType(FixLocation const *location) {
    return LinterError(location, LinterErrorType::ResultTypeDoesNotMatchExprType);
  }

  static LinterError NonNormalFilename(FixLocation const *location) {
    return LinterError(location, LinterErrorType::NonNormalFilename);
  }

private:
  FixLocation const *location;
  LinterErrorType type;
};

class FixLocationLinter {
public:
  FixLocationLinter(FixLocalization &fixLocalization, bool shouldRepair)
  : fixLocalization(fixLocalization),
    errors(),
    shouldRepair(shouldRepair)
  {}

  void run(clang::ASTContext &context);
  void repair(clang::ASTContext &context);
  void validate(clang::ASTContext &context);

  std::optional<LinterError> validate(AstLinkedFixLocation const &location);

  std::unique_ptr<FixLocation> repair(AstLinkedFixLocation const &location);

  void save(std::string const &saveToFilename) const;

  bool hasFoundErrors() const;

private:
  FixLocalization &fixLocalization;
  std::vector<LinterError> errors;
  bool shouldRepair;
};

}

