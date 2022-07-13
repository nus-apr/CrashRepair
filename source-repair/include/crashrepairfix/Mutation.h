#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "SourceLocation.h"
#include "AstLinkedFixLocation.h"

namespace crashrepairfix {

class Replacement {
public:
  Replacement(
    std::string const &filename,
    size_t offset,
    size_t length,
    std::string text
  )
  : filename(filename), offset(offset), length(length), text(text) {}

  // Creates a replacement that prepends a given source text immediately before a statement
  static Replacement prepend(std::string const &text, AstLinkedFixLocation const &location) {
    return prepend(text, location.getStmt(), location.getContext());
  }
  static Replacement prepend(std::string const &text, clang::Stmt const *stmt, clang::ASTContext const &context) {
    return prepend(text, stmt->getBeginLoc(), context.getSourceManager());
  }
  static Replacement prepend(std::string const &text, clang::SourceLocation const &location, clang::SourceManager const &sourceManager) {
    return prepend(text, sourceManager.getFilename(location).str(), sourceManager.getFileOffset(location));
  }
  static Replacement prepend(std::string const &text, std::string const &filename, size_t offset) {
    return Replacement(filename, offset, 0, text);
  }

  std::string const & getFilename() const {
    return filename;
  }

  std::string const & getText() const {
    return text;
  }

  size_t getOffset() const {
    return offset;
  }

  size_t getLength() const {
    return length;
  }

  nlohmann::json toJson() const {
    return {
      {"filename", filename},
      {"offset", offset},
      {"length", length},
      {"text", text}
    };
  }

private:
  std::string filename;
  size_t offset;
  size_t length;
  std::string text;
};

class Mutation {
public:
  Mutation(
    size_t id,
    SourceLocation const &location,
    std::vector<Replacement> const &replacements,
    std::string const &diff
  ) : id(id), location(location), replacements(replacements), diff(diff) {}

  size_t getId() const {
    return id;
  }

  nlohmann::json toJson() const {
    nlohmann::json j = {
      {"id", id},
      {"location", location.toString()},
      {"diff", diff}
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
  std::string diff;
};

}
