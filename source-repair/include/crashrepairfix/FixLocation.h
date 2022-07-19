#pragma once

#include <nlohmann/json.hpp>

#include "SourceLocation.h"
#include "Expr/Expr.h"
#include "Expr/Parser.h"

namespace crashrepairfix {

class FixLocation {
private:
  SourceLocation sourceLocation;
  std::unique_ptr<Expr> constraint;

public:
  FixLocation(
    SourceLocation &sourceLocation,
    std::unique_ptr<Expr> constraint
  ) : sourceLocation(sourceLocation), constraint(std::move(constraint)) {}

  static std::unique_ptr<FixLocation> fromJSON(nlohmann::json j) {
    SourceLocation location = SourceLocation::fromString(j["location"]);
    auto expr = parse(j["constraint"]);
    return std::make_unique<FixLocation>(location, std::move(expr));
  }

  SourceLocation const & getLocation() const {
    return sourceLocation;
  }

  Expr * getConstraint() {
    return constraint.get();
  }
  Expr const * getConstraint() const {
    return constraint.get();
  }
};

}
