#include <crashrepairfix/ProgramStates.h>

#include <spdlog/spdlog.h>

namespace crashrepairfix {

ProgramStates::Variable ProgramStates::Variable::fromJSON(nlohmann::json const &j) {
  std::string name = j["name"];
  auto type = Expr::resultTypeFromString(j["kind"]);
  auto declaredAt = SourceLocation::fromString(j["declaredAt"]);
  return Variable(name, type, declaredAt);
}

ProgramStates::Values ProgramStates::Values::fromJSON(
  std::vector<Variable> const &variables,
  nlohmann::json const &j
) {
  std::unordered_map<Variable const *, std::variant<double, long>> values;

  for (Variable const &variable : variables) {
    std::variant<double, long> value;
    switch (variable.type) {
      case ResultType::Int:
      case ResultType::Pointer:
        value = j[variable.name].get<long>();
        break;
      case ResultType::Float:
        value = j[variable.name].get<double>();
        break;
      default:
        assert (false);
    }
    values[&variable] = value;
  }

  return Values(std::move(values));
}

ProgramStates ProgramStates::fromJSON(nlohmann::json const &j) {
  std::vector<Variable> variables;
  for (auto jVariable : j["variables"]) {
    variables.push_back(Variable::fromJSON(jVariable));
  }

  std::vector<Values> values;
  for (auto jValues : j["values"]) {
    values.push_back(Values::fromJSON(variables, jValues));
  }

  return ProgramStates(variables, values);
}

z3::expr ProgramStates::Values::toZ3(z3::context &z3c) const {
  z3::expr_vector operands(z3c);

  auto intToVar = [&z3c, &operands](Variable const *variable, long value) {
    auto lhs = z3c.int_const(variable->name.c_str());
    auto rhs = z3c.int_val(value);
    operands.push_back(lhs == rhs);
  };

  auto floatToVar = [&z3c, &operands](Variable const *variable, double value) {
    auto lhs = z3c.real_const(variable->name.c_str());
    auto rhs = z3c.fpa_val(value);
    operands.push_back(lhs == rhs);
  };

  for (auto const & [variable, value] : values) {
    switch (variable->type) {
      case ResultType::Int:
      case ResultType::Pointer:
        intToVar(variable, std::get<long>(value));
        break;

      case ResultType::Float:
        floatToVar(variable, std::get<double>(value));
        break;

      default:
        assert (false);
    }
  }

  return z3::mk_and(operands);
}


}
