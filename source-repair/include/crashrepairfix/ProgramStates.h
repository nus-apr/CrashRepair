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
    static std::unique_ptr<Values> fromJSON(
      std::vector<std::unique_ptr<Variable>> const &variables,
      nlohmann::json const &j
    );

    Values(std::unordered_map<Variable const *, std::variant<double, long>> values) : values(values) {}

    z3::expr toZ3(z3::context &z3c) const;

  private:
    std::unordered_map<
      Variable const *,
      std::variant<double, long>
    > values;
  };

  static ProgramStates fromJSON(nlohmann::json const &j);

  std::vector<std::unique_ptr<Values>> const & getValues() const {
    return values;
  }
  std::vector<std::unique_ptr<Variable>> const & getVariables() const {
    return variables;
  }

  ProgramStates(ProgramStates const &other) = delete;
  ProgramStates(ProgramStates&& other) noexcept :
    variables(std::move(other.variables)), values(std::move(other.values))
  {}

private:
  std::vector<std::unique_ptr<Variable>> variables;
  std::vector<std::unique_ptr<Values>> values;

  ProgramStates(
    std::vector<std::unique_ptr<Variable>> &variables,
    std::vector<std::unique_ptr<Values>> &values
  ) : variables(std::move(variables)), values(std::move(values)) {}
};

}
