#include <crashrepairfix/ProgramStates.h>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

namespace crashrepairfix {

std::string ProgramStates::Variable::toString() const {
  return fmt::format("Variable({}, {})", name, Expr::resultTypeToString(type));
}

std::unique_ptr<ProgramStates::Variable> ProgramStates::Variable::fromJSON(nlohmann::json const &j) {
  std::string name = j["name"];
  auto type = Expr::resultTypeFromString(j["type"]);
  auto variable = std::make_unique<Variable>(name, type);
  spdlog::debug("loaded variable: {}", variable->toString());
  return variable;
}

std::unique_ptr<ProgramStates::Values> ProgramStates::Values::fromJSON(
  std::vector<std::unique_ptr<Variable>> const &variables,
  nlohmann::json const &j
) {
  std::unordered_map<Variable const *, std::variant<double, long>> values;

  for (auto const &variable : variables) {
    std::variant<double, long> value;
    switch (variable->type) {
      case ResultType::Int:
      case ResultType::Pointer:
        value = j[variable->name].get<long>();
        break;
      case ResultType::Float:
        value = j[variable->name].get<double>();
        break;
      default:
        assert (false);
    }
    values[variable.get()] = value;
  }

  return std::make_unique<Values>(std::move(values));
}

ProgramStates ProgramStates::fromJSON(nlohmann::json const &j) {
  std::vector<std::unique_ptr<Variable>> variables;
  for (auto jVariable : j["variables"]) {
    variables.push_back(Variable::fromJSON(jVariable));
  }

  std::vector<std::unique_ptr<Values>> values;
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
