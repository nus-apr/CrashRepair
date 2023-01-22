#pragma once

#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>

#include <z3++.h>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"
#include "Expr/Expr.h"

namespace crashrepairfix {

class ProgramStates {
public:

  class Values;

  class Variable {
  public:
    static std::unique_ptr<Variable> fromJSON(nlohmann::json const &j);

    Variable(std::string const &name, ResultType type)
    : name(name), type(type) {}
    Variable(Variable const &other) noexcept
    : name(other.name),
      type(other.type)
    {}

    std::string toString() const;
    std::string const & getName() const;
    ResultType getResultType() const;

  private:
    std::string const name;
    ResultType const type;

    friend class Values;
  };

  class Values {
  public:
    static std::unique_ptr<Values> load(
      std::vector<std::unique_ptr<Variable>> const &variables,
      std::string const &valuesFilename
    );

    Values(std::unordered_map<Variable const *, std::variant<double, long, unsigned long>> values) : values(values) {}

    z3::expr toZ3(z3::context &z3c) const;

  private:
    std::unordered_map<
      Variable const *,
      std::variant<double, long, unsigned long>
    > values;
  };

  static ProgramStates fromJSON(nlohmann::json const &j, std::string const &valuesFilename);

  std::vector<std::unique_ptr<Values>> const & getValues() const {
    // TODO load values if not already loaded
    return values;
  }
  std::vector<std::unique_ptr<Variable>> const & getVariables() const {
    return variables;
  }

  ProgramStates(ProgramStates const &other) noexcept :
    valuesFilename(other.valuesFilename),
    variables(),
    values()
  {
    variables.reserve(other.variables.size());
    for (auto &variable : other.variables) {
      variables.push_back(std::make_unique<Variable>(variable->getName(), variable->getResultType()));
    }
    loadValues();
  }
  ProgramStates(ProgramStates&& other) noexcept :
    valuesFilename(other.valuesFilename),
    variables(std::move(other.variables)),
    values(std::move(other.values))
  {}

  std::string getValuesFilename() const {
    return valuesFilename;
  }

private:
  std::string valuesFilename;
  std::vector<std::unique_ptr<Variable>> variables;
  std::vector<std::unique_ptr<Values>> values;

  ProgramStates(
    std::string const &valuesFilename,
    std::vector<std::unique_ptr<Variable>> &variables
  ) : valuesFilename(valuesFilename),
      variables(std::move(variables)),
      values()
  {}

  void loadValues();
};

}
