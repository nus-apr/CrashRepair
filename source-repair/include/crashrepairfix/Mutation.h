// Mutation::toJSON
// - id
// - location
// - replacements
// Mutations::toJSON
// ProgramMutator

#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"

namespace crashrepairfix {

class Replacement {
public:
  Replacement(size_t offset, size_t length, std::string text)
  : offset(offset), length(length), text(text) {}

  nlohmann::json toJson() const {
    return {
      {"offset", offset},
      {"length", length},
      {"text", text}
    };
  }

private:
  size_t offset;
  size_t length;
  std::string text;
};

class Mutation {
public:
  Mutation(
    size_t id,
    SourceLocation const &location,
    std::vector<Replacement> const &replacements
  ) : id(id), location(location), replacements(replacements) {}

  size_t getId() const {
    return id;
  }

  nlohmann::json toJson() const {
    nlohmann::json j = {
      {"id", id},
      {"location", location.toString()}
    };

    j["replacements"] = nlohmann::json::array();
    for (auto &replacement : replacements) {
      j["replacements"].push_back(replacement.toJson());
    }

    return j;
  }

private:
  size_t id;
  SourceLocation location;
  std::vector<Replacement> replacements;
};

}
