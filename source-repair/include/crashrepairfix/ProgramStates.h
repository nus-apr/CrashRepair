#pragma once

#include <memory>
#include <unordered_map>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"
#include "Expr/Expr.h"

namespace crashrepairfix {

class ProgramStates {
public:

  class Values;

  class Variable {
  public:
    static Variable fromJSON(nlohmann::json const &j);

  private:
    std::string const name;
    ResultType const type;
    SourceLocation const declaredAt;

    Variable(std::string const &name, ResultType type, SourceLocation declaredAt)
    : name(name), type(type), declaredAt(declaredAt) {}

    friend class Values;
  };

  class Values {
  public:
    static Values fromJSON(
      std::vector<Variable> const &variables,
      nlohmann::json const &j
    );


    // z3::expr toZ3(z3::context &z3c) const;

  private:
    std::unordered_map<
      Variable const *,
      std::variant<double, long>
    > values;

    Values(std::unordered_map<Variable const *, std::variant<double, long>> values) : values(values) {}
  };

  static ProgramStates fromJSON(nlohmann::json const &j);

  // TODO add iterator over values

private:
  std::vector<Variable> variables;
  std::vector<Values> values;

  ProgramStates(
    std::vector<Variable> &variables,
    std::vector<Values> &values
  ) : variables(std::move(variables)), values(std::move(values)) {}
};

}
