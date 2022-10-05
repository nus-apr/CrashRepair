#pragma once

#include <filesystem>

#include <nlohmann/json.hpp>

#include "ProgramStates.h"
#include "SourceLocation.h"
#include "Expr/Expr.h"
#include "Expr/Parser.h"

namespace fs = std::filesystem;

namespace crashrepairfix {

class FixLocation {
private:
  SourceLocation sourceLocation;
  std::unique_ptr<Expr> constraint;
  ProgramStates states;

public:
  FixLocation(
    SourceLocation &sourceLocation,
    std::unique_ptr<Expr> constraint,
    ProgramStates &states
  ) : sourceLocation(sourceLocation),
      constraint(std::move(constraint)),
      states(std::move(states))
  {}

  /** Returns a nullptr if unable to build fix location */
  static std::unique_ptr<FixLocation> fromJSON(
    nlohmann::json j,
    std::string const &localizationFilename
  ) {
    SourceLocation location = SourceLocation::fromString(j["location"]);
    auto expr = parse(j["constraint"]);

    if (expr == nullptr) {
      spdlog::warn("skipping fix location: unable to parse constraint: {}", j["constraint"]);
      return std::unique_ptr<FixLocation>(nullptr);
    }

    auto localizationFilepath = fs::path(localizationFilename);
    auto localizationDirectory = localizationFilepath.parent_path();
    std::string valuesFilename = j["values-file"];
    auto valuesPath = localizationDirectory / fs::path("values") / valuesFilename;
    auto states = ProgramStates::fromJSON(j, valuesPath.string());
    return std::make_unique<FixLocation>(location, std::move(expr), states);
  }

  SourceLocation const & getLocation() const {
    return sourceLocation;
  }

  ProgramStates const & getStates() const {
    return states;
  }

  Expr * getConstraint() {
    return constraint.get();
  }
  Expr const * getConstraint() const {
    return constraint.get();
  }
};

}
