// Mutation::toJSON
// - id
// - location
// - replacements
// Mutations::toJSON
// ProgramMutator

#pragma once

#include <nlohmann/json.hpp>

namespace crashrepairfix {

class Mutation {
public:

  size_t getId() const {
    return id;
  }

  // Insert, Replace
  std::vector<Edit> const & getEdits() const {

  }

  virtual nlohmann::json toJSON() const = 0;

private:
  size_t id;
};

}
