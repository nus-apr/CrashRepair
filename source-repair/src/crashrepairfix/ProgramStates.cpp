#include <crashrepairfix/ProgramStates.h>

#include <fstream>

#include <spdlog/spdlog.h>
#include <spdlog/fmt/fmt.h>

namespace crashrepairfix {

void ProgramStates::loadValues() {
  std::ifstream fh(valuesFilename);

  spdlog::debug("loading state values from file: {}", valuesFilename);

  if (!fh.is_open()) {
    spdlog::error("failed to open state values file: {}", valuesFilename);
    abort();
  }

  // read the header
  std::vector<Variable const *> columns;
  std::string line;
  if (!std::getline(fh, line)) {
    spdlog::error("failed to read header from state values file");
    abort();
  }
  remove_trailing_newline(line);

  spdlog::debug("retrieved header line from state values file: {}", line);

  for (auto column : split(line, ';')) {
    strip_whitespace(column);

    // find the corresponding variable with the same name as the column
    Variable const *matchingVariable;
    for (auto const &variable : variables) {
      if (variable->getName() == column) {
        matchingVariable = variable.get();
        break;
      }
    }

    // produce an error if no match is found
    if (matchingVariable == nullptr) {
      spdlog::error("failed to match column to variable: \"{}\"", column);

      for (char character : column) {
        if (!isprint(static_cast<unsigned char>(character))) {
          spdlog::error("column contains unprintable character: {}", escape_character(character));
        }
      }

      spdlog::error("known variables:");
      for (auto const &variable : variables) {
        spdlog::error("* \"{}\"", variable->getName());
      }
      abort();
    }

    // otherwise record the variable
    columns.push_back(matchingVariable);
  }

  size_t numColumns = columns.size();
  spdlog::debug("state values file contains {} columns", numColumns);

  // read each row
  size_t lineNumber = 0;
  while (std::getline(fh, line)) {
    remove_trailing_newline(line);
    lineNumber++;

    auto cells = split(line, ';');
    size_t numColumnsInRow = cells.size();
    if (cells.size() != numColumns) {
      spdlog::error("failed to read line {}: expected {} columns but has {}", lineNumber, numColumns, numColumnsInRow);
      abort();
    }

    std::unordered_map<Variable const *, std::variant<double, long>> row;
    for (int col = 0; col < numColumns; col++) {
      auto cellString = cells[col];
      strip_whitespace(cellString);
      auto const *variable = columns[col];
      std::variant<double, long> value;

      switch (variable->getResultType()) {
        case ResultType::Int:
        case ResultType::Pointer:
          value = std::stol(cellString);
          break;
        case ResultType::Float:
          value = std::stod(cellString);
          break;
        row[variable] = value;
      }
    }

    values.push_back(std::make_unique<Values>(std::move(row)));
  }

  fh.close();
}

std::string ProgramStates::Variable::toString() const {
  return fmt::format("Variable({}, {})", name, Expr::resultTypeToString(type));
}

ResultType ProgramStates::Variable::getResultType() const {
  return type;
}

std::string const & ProgramStates::Variable::getName() const {
  return name;
}

std::unique_ptr<ProgramStates::Variable> ProgramStates::Variable::fromJSON(nlohmann::json const &j) {
  std::string name = j["name"];
  auto type = Expr::resultTypeFromString(j["type"]);
  auto variable = std::make_unique<Variable>(name, type);
  spdlog::debug("loaded variable: {}", variable->toString());
  return variable;
}


ProgramStates ProgramStates::fromJSON(
  nlohmann::json const &j,
  std::string const &valuesFilename
) {
  std::vector<std::unique_ptr<Variable>> variables;
  for (auto jVariable : j["variables"]) {
    variables.push_back(Variable::fromJSON(jVariable));
  }
  auto states = ProgramStates(valuesFilename, variables);
  states.loadValues();
  return states;
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
