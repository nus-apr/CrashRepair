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
    variables.push_back(std::move(Variable::fromJSON(jVariable)));
  }

  std::vector<Values> values;
  for (auto jValues : j["values"]) {
    values.push_back(std::move(Values::fromJSON(variables, jValues)));
  }

  return ProgramStates(variables, values);
}

}
