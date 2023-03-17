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
  size_t distance;

public:
  FixLocation(
    SourceLocation const &sourceLocation,
    std::unique_ptr<Expr> constraint,
    ProgramStates &states,
    size_t distance
  ) : sourceLocation(sourceLocation),
      constraint(std::move(constraint)),
      states(std::move(states)),
      distance(distance)
  {}

  FixLocation(
    SourceLocation const &sourceLocation,
    std::unique_ptr<Expr> constraint,
    ProgramStates const &states,
    size_t distance
  ) : sourceLocation(sourceLocation),
      constraint(std::move(constraint)),
      states(states),
      distance(distance)
  {}

  /** Returns a nullptr if unable to build fix location */
  static std::unique_ptr<FixLocation> fromJSON(
    nlohmann::json j,
    std::string const &localizationFilename
  ) {
    SourceLocation location = SourceLocation::fromString(j["location"]);
    auto expr = parse(j["constraint"]);
    size_t distance = j["distance"];

    if (expr == nullptr) {
      spdlog::warn("skipping fix location: unable to parse constraint: {}", j["constraint"]);
      return std::unique_ptr<FixLocation>(nullptr);
    }

    auto localizationFilepath = fs::path(localizationFilename);
    auto localizationDirectory = localizationFilepath.parent_path();
    std::string valuesFilename = j["values-file"];
    auto valuesPath = localizationDirectory / fs::path("values") / valuesFilename;
    auto states = ProgramStates::fromJSON(j, valuesPath.string());
    return std::make_unique<FixLocation>(location, std::move(expr), states, distance);
  }

  nlohmann::json toJSON() const {
    auto variablesJson = nlohmann::json::array();
    for (auto &variable : states.getVariables()) {
      variablesJson.push_back(variable->toJSON());
    }
    return {
      {"location", sourceLocation.toString()},
      {"distance", distance},
      {"constraint", constraint->toString()},
      {"variables", variablesJson},
      {"values-file", states.getValuesFilename()}
    };
  }

  void setLocation(SourceLocation const &other) {
    sourceLocation = other;
  }

  size_t getDistance() const {
    return distance;
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
